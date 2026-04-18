use std::{collections::HashMap, net::SocketAddr, str::FromStr, sync::Arc};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, FromRow, PgPool};
use tokio::sync::RwLock;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{info, warn};
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    session_ttl_hours: i64,
    session_token_pepper: String,
    webauthn: Arc<Webauthn>,
    ceremonies: Arc<RwLock<HashMap<Uuid, CeremonyState>>>,
}

enum CeremonyState {
    Registration {
        subject_id: Uuid,
        passkey_name: String,
        state: PasskeyRegistration,
        expires_at: DateTime<Utc>,
    },
    Authentication {
        subject_id: Uuid,
        state: PasskeyAuthentication,
        expires_at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SubjectKind {
    Member,
    CommunityStaff,
    PlatformStaff,
}

impl SubjectKind {
    fn as_db_str(&self) -> &'static str {
        match self {
            SubjectKind::Member => "member",
            SubjectKind::CommunityStaff => "community_staff",
            SubjectKind::PlatformStaff => "platform_staff",
        }
    }
}

impl FromStr for SubjectKind {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "member" => Ok(Self::Member),
            "community_staff" => Ok(Self::CommunityStaff),
            "platform_staff" => Ok(Self::PlatformStaff),
            _ => Err(AppError::bad_request("invalid subject type")),
        }
    }
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    error: String,
}

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            Json(ApiErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AppError {}

impl From<sqlx::Error> for AppError {
    fn from(value: sqlx::Error) -> Self {
        warn!("database error: {value}");
        AppError::internal("database error")
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
    now: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct SubjectRow {
    id: Uuid,
    _person_id: Uuid,
    subject_type: String,
    email: String,
    display_name: String,
    mfa_enabled: bool,
}

#[derive(Debug, FromRow)]
struct SessionRow {
    id: Uuid,
    auth_method: String,
    device_name: String,
    user_agent: Option<String>,
    ip: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

struct CreatedSession {
    row: SessionRow,
    token_plaintext: String,
}

#[derive(Debug, Deserialize)]
struct PasswordLoginRequest {
    email: String,
    password: String,
    device_name: Option<String>,
    device_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OtpRequestPayload {
    email: String,
}

#[derive(Debug, Deserialize)]
struct OtpVerifyRequest {
    email: String,
    code: String,
    device_name: Option<String>,
    device_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PasskeyRegisterStartRequest {
    email: String,
    passkey_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PasskeyRegisterFinishRequest {
    email: String,
    ceremony_id: Uuid,
    credential: Value,
}

#[derive(Debug, Deserialize)]
struct PasskeyLoginStartRequest {
    email: String,
}

#[derive(Debug, Deserialize)]
struct PasskeyLoginFinishRequest {
    email: String,
    ceremony_id: Uuid,
    credential: Value,
    device_name: Option<String>,
    device_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MfaVerifyRequest {
    ticket_id: Uuid,
    code: String,
    device_name: Option<String>,
    device_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RevokeSessionRequest {
    session_id: Uuid,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum AuthResponse {
    Authenticated {
        token: String,
        session: SessionInfo,
        subject_id: Uuid,
        subject_type: String,
    },
    MfaRequired {
        ticket_id: Uuid,
        otp_hint: String,
    },
}

#[derive(Debug, Serialize)]
struct SubjectProfile {
    id: Uuid,
    person_id: Uuid,
    subject_type: String,
    email: String,
    display_name: String,
    mfa_enabled: bool,
}

#[derive(Debug, Serialize)]
struct LinkedSubject {
    id: Uuid,
    person_id: Uuid,
    subject_type: String,
    email: String,
    display_name: String,
    mfa_enabled: bool,
    is_current: bool,
}

#[derive(Debug, Serialize)]
struct SessionInfo {
    id: Uuid,
    auth_method: String,
    device_name: String,
    user_agent: Option<String>,
    ip: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    is_current: bool,
}

#[derive(Debug, Serialize)]
struct OtpRequestResponse {
    otp_hint: String,
    expires_in_sec: i64,
}

#[derive(Debug, Serialize)]
struct PasskeyCeremonyResponse {
    ceremony_id: Uuid,
    options: Value,
}

#[derive(Debug, Serialize)]
struct LogoutResponse {
    revoked: bool,
}

#[derive(Debug)]
struct AuthContext {
    subject_id: Uuid,
    session_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct UpdateProfileRequest {
    display_name: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/multi_subject_auth".to_string());
    let session_token_pepper =
        std::env::var("SESSION_TOKEN_PEPPER").unwrap_or_else(|_| "dev-only-change-me".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    seed_data(&pool).await?;

    let rp_id = std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let rp_origin = std::env::var("WEBAUTHN_RP_ORIGIN").unwrap_or_else(|_| "http://localhost:5173".to_string());
    let rp_name = std::env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "Multi Subject Auth".to_string());

    let origin = Url::parse(&rp_origin).map_err(|_| AppError::internal("invalid WEBAUTHN_RP_ORIGIN"))?;
    let webauthn = WebauthnBuilder::new(&rp_id, &origin)
        .map_err(|_| AppError::internal("failed to configure webauthn"))?
        .rp_name(&rp_name)
        .build()
        .map_err(|_| AppError::internal("failed to build webauthn"))?;

    let app_state = AppState {
        pool,
        session_ttl_hours: 24 * 7,
        session_token_pepper,
        webauthn: Arc::new(webauthn),
        ceremonies: Arc::new(RwLock::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/auth/{subject}/password/login", post(password_login))
        .route("/auth/{subject}/otp/request", post(request_otp))
        .route("/auth/{subject}/otp/verify", post(verify_otp))
        .route("/auth/{subject}/passkey/register/start", post(passkey_register_start))
        .route("/auth/{subject}/passkey/register/finish", post(passkey_register_finish))
        .route("/auth/{subject}/passkey/login/start", post(passkey_login_start))
        .route("/auth/{subject}/passkey/login/finish", post(passkey_login_finish))
        .route("/auth/{subject}/mfa/verify", post(verify_mfa))
        .route("/me/profile", get(me_profile))
        .route("/me/profile", post(update_profile))
        .route("/me/linked-subjects", get(me_linked_subjects))
        .route("/me/sessions", get(list_sessions))
        .route("/me/sessions/revoke", post(revoke_session))
        .route("/auth/logout", post(logout))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let addr: SocketAddr = "0.0.0.0:8080".parse()?;
    info!("backend listening at {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn seed_data(pool: &PgPool) -> Result<(), AppError> {
    let users = vec![
        (
            SubjectKind::Member,
            "member@demo.local",
            "Demo Member",
            "Member#123",
            false,
        ),
        (
            SubjectKind::CommunityStaff,
            "community@demo.local",
            "Community Operator",
            "Community#123",
            false,
        ),
        (
            SubjectKind::PlatformStaff,
            "platform@demo.local",
            "Platform Operator",
            "Platform#123",
            true,
        ),
    ];

    for (kind, email, display_name, password, mfa_enabled) in users {
        let normalized_email = email.trim().to_lowercase();
        let person_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO persons (id, primary_email)
            VALUES ($1, $2)
            ON CONFLICT (primary_email) DO NOTHING
            "#,
        )
        .bind(person_id)
        .bind(&normalized_email)
        .execute(pool)
        .await?;

        let person: (Uuid,) =
            sqlx::query_as("SELECT id FROM persons WHERE primary_email = $1")
                .bind(&normalized_email)
                .fetch_one(pool)
                .await?;

        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO subjects (id, person_id, subject_type, email, display_name, mfa_enabled)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (subject_type, email)
            DO UPDATE SET person_id = EXCLUDED.person_id, display_name = EXCLUDED.display_name, mfa_enabled = EXCLUDED.mfa_enabled
            "#,
        )
        .bind(id)
        .bind(person.0)
        .bind(kind.as_db_str())
        .bind(&normalized_email)
        .bind(display_name)
        .bind(mfa_enabled)
        .execute(pool)
        .await?;

        let subject: SubjectRow = sqlx::query_as(
            r#"
            SELECT s.id, s.person_id AS _person_id, s.subject_type, s.email, COALESCE(sp.display_name, s.display_name) AS display_name, s.mfa_enabled
            FROM subjects s
            LEFT JOIN subject_profiles sp ON sp.subject_id = s.id
            WHERE s.subject_type = $1 AND s.email = $2
            "#,
        )
        .bind(kind.as_db_str())
        .bind(&normalized_email)
        .fetch_one(pool)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO subject_profiles(subject_id, display_name)
            VALUES ($1, $2)
            ON CONFLICT (subject_id)
            DO UPDATE SET display_name = EXCLUDED.display_name, updated_at = NOW()
            "#,
        )
        .bind(subject.id)
        .bind(display_name)
        .execute(pool)
        .await?;

        let hash = hash_secret(password)?;
        sqlx::query(
            r#"
            INSERT INTO password_credentials(subject_id, password_hash)
            VALUES ($1, $2)
            ON CONFLICT (subject_id)
            DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = NOW()
            "#,
        )
        .bind(subject.id)
        .bind(hash)
        .execute(pool)
        .await?;
    }

    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        now: Utc::now(),
    })
}

async fn password_login(
    Path(subject): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<PasswordLoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let subject_kind = SubjectKind::from_str(&subject)?;
    let subject = load_subject_by_email(&state.pool, &subject_kind, &payload.email).await?;

    let row: (String,) = sqlx::query_as("SELECT password_hash FROM password_credentials WHERE subject_id = $1")
        .bind(subject.id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| AppError::unauthorized("password not configured"))?;

    let verified = verify_secret(&row.0, &payload.password);
    if !verified {
        return Err(AppError::unauthorized("invalid credentials"));
    }

    if subject.mfa_enabled {
        let ticket = create_mfa_ticket(&state.pool, subject.id, "password").await?;
        let (otp, _) = create_otp_code(&state.pool, subject.id, "mfa").await?;
        info!("mfa otp generated for subject {} ({}) code={}", subject.id, subject.subject_type, otp);
        return Ok(Json(AuthResponse::MfaRequired {
            ticket_id: ticket,
            otp_hint: "Check your authenticator channel for OTP.".to_string(),
        }));
    }

    let device_name = payload
        .device_name
        .unwrap_or_else(|| "Unknown Device".to_string());
    let device_fingerprint =
        resolve_device_fingerprint(payload.device_fingerprint.as_deref(), &device_name, &headers);

    let session = create_session(
        &state,
        &subject,
        "password",
        &device_name,
        &device_fingerprint,
        &headers,
    )
    .await?;

    Ok(Json(AuthResponse::Authenticated {
        token: session.token_plaintext.clone(),
        session: to_session_info(session.row, true),
        subject_id: subject.id,
        subject_type: subject.subject_type,
    }))
}

async fn request_otp(
    Path(subject): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<OtpRequestPayload>,
) -> Result<Json<OtpRequestResponse>, AppError> {
    let subject_kind = SubjectKind::from_str(&subject)?;
    let subject = load_subject_by_email(&state.pool, &subject_kind, &payload.email).await?;

    let (otp, expires_at) = create_otp_code(&state.pool, subject.id, "login").await?;
    info!("login otp generated for subject {} ({}) code={}", subject.id, subject.subject_type, otp);
    let ttl = (expires_at - Utc::now()).num_seconds().max(0);

    Ok(Json(OtpRequestResponse {
        otp_hint: "Use the code within 5 minutes (delivered through your OTP channel).".to_string(),
        expires_in_sec: ttl,
    }))
}

async fn verify_otp(
    Path(subject): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<OtpVerifyRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let subject_kind = SubjectKind::from_str(&subject)?;
    let subject = load_subject_by_email(&state.pool, &subject_kind, &payload.email).await?;

    consume_otp_code(&state.pool, subject.id, "login", &payload.code).await?;

    let device_name = payload
        .device_name
        .unwrap_or_else(|| "Unknown Device".to_string());
    let device_fingerprint =
        resolve_device_fingerprint(payload.device_fingerprint.as_deref(), &device_name, &headers);

    let session =
        create_session(&state, &subject, "otp", &device_name, &device_fingerprint, &headers).await?;

    Ok(Json(AuthResponse::Authenticated {
        token: session.token_plaintext.clone(),
        session: to_session_info(session.row, true),
        subject_id: subject.id,
        subject_type: subject.subject_type,
    }))
}

async fn passkey_register_start(
    Path(subject): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<PasskeyRegisterStartRequest>,
) -> Result<Json<PasskeyCeremonyResponse>, AppError> {
    let subject_kind = SubjectKind::from_str(&subject)?;
    let subject = load_subject_by_email(&state.pool, &subject_kind, &payload.email).await?;

    let passkey_name = payload
        .passkey_name
        .unwrap_or_else(|| "Primary Device".to_string());

    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(
            subject.id,
            &subject.email,
            &subject.display_name,
            Some(vec![]),
        )
        .map_err(map_webauthn_err)?;

    let ceremony_id = Uuid::new_v4();
    state.ceremonies.write().await.insert(
        ceremony_id,
        CeremonyState::Registration {
            subject_id: subject.id,
            passkey_name,
            state: reg_state,
            expires_at: Utc::now() + Duration::minutes(10),
        },
    );

    Ok(Json(PasskeyCeremonyResponse {
        ceremony_id,
        options: serde_json::to_value(ccr).map_err(|_| AppError::internal("invalid ceremony payload"))?,
    }))
}

async fn passkey_register_finish(
    Path(subject): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<PasskeyRegisterFinishRequest>,
) -> Result<Json<LogoutResponse>, AppError> {
    let subject_kind = SubjectKind::from_str(&subject)?;
    let subject = load_subject_by_email(&state.pool, &subject_kind, &payload.email).await?;

    let challenge = state
        .ceremonies
        .write()
        .await
        .remove(&payload.ceremony_id)
        .ok_or_else(|| AppError::unauthorized("ceremony expired"))?;

    let (state_reg, passkey_name) = match challenge {
        CeremonyState::Registration {
            subject_id,
            state: reg_state,
            expires_at,
            passkey_name,
        } => {
            if subject_id != subject.id {
                return Err(AppError::unauthorized("ceremony subject mismatch"));
            }
            if expires_at < Utc::now() {
                return Err(AppError::unauthorized("ceremony expired"));
            }
            (reg_state, passkey_name)
        }
        _ => return Err(AppError::bad_request("invalid ceremony type")),
    };

    let reg_credential: RegisterPublicKeyCredential =
        serde_json::from_value(payload.credential).map_err(|_| AppError::bad_request("invalid credential"))?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&reg_credential, &state_reg)
        .map_err(map_webauthn_err)?;

    let passkey_json = serde_json::to_value(&passkey).map_err(|_| AppError::internal("failed to serialize passkey"))?;

    sqlx::query(
        r#"
        INSERT INTO passkey_credentials(id, subject_id, passkey_name, token_hash, credential_id, passkey_json, last_used_at)
        VALUES ($1, $2, $3, NULL, NULL, $4, NOW())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(subject.id)
    .bind(passkey_name)
    .bind(passkey_json)
    .execute(&state.pool)
    .await?;

    Ok(Json(LogoutResponse { revoked: true }))
}

async fn passkey_login_start(
    Path(subject): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<PasskeyLoginStartRequest>,
) -> Result<Json<PasskeyCeremonyResponse>, AppError> {
    let subject_kind = SubjectKind::from_str(&subject)?;
    let subject = load_subject_by_email(&state.pool, &subject_kind, &payload.email).await?;

    let rows: Vec<(Value,)> = sqlx::query_as(
        "SELECT passkey_json FROM passkey_credentials WHERE subject_id = $1 AND passkey_json IS NOT NULL",
    )
    .bind(subject.id)
    .fetch_all(&state.pool)
    .await?;

    if rows.is_empty() {
        return Err(AppError::bad_request("no passkeys enrolled"));
    }

    let passkeys: Vec<Passkey> = rows
        .into_iter()
        .filter_map(|(v,)| serde_json::from_value::<Passkey>(v).ok())
        .collect();

    if passkeys.is_empty() {
        return Err(AppError::bad_request("no valid passkeys enrolled"));
    }

    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(map_webauthn_err)?;

    let ceremony_id = Uuid::new_v4();
    state.ceremonies.write().await.insert(
        ceremony_id,
        CeremonyState::Authentication {
            subject_id: subject.id,
            state: auth_state,
            expires_at: Utc::now() + Duration::minutes(10),
        },
    );

    Ok(Json(PasskeyCeremonyResponse {
        ceremony_id,
        options: serde_json::to_value(rcr).map_err(|_| AppError::internal("invalid ceremony payload"))?,
    }))
}

async fn passkey_login_finish(
    Path(subject): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<PasskeyLoginFinishRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let subject_kind = SubjectKind::from_str(&subject)?;
    let subject = load_subject_by_email(&state.pool, &subject_kind, &payload.email).await?;

    let challenge = state
        .ceremonies
        .write()
        .await
        .remove(&payload.ceremony_id)
        .ok_or_else(|| AppError::unauthorized("ceremony expired"))?;

    let auth_state = match challenge {
        CeremonyState::Authentication {
            subject_id,
            state: auth_state,
            expires_at,
        } => {
            if subject_id != subject.id {
                return Err(AppError::unauthorized("ceremony subject mismatch"));
            }
            if expires_at < Utc::now() {
                return Err(AppError::unauthorized("ceremony expired"));
            }
            auth_state
        }
        _ => return Err(AppError::bad_request("invalid ceremony type")),
    };

    let credential: PublicKeyCredential =
        serde_json::from_value(payload.credential).map_err(|_| AppError::bad_request("invalid credential"))?;

    state
        .webauthn
        .finish_passkey_authentication(&credential, &auth_state)
        .map_err(map_webauthn_err)?;
    sqlx::query("UPDATE passkey_credentials SET last_used_at = NOW() WHERE subject_id = $1")
        .bind(subject.id)
        .execute(&state.pool)
        .await?;

    if subject.mfa_enabled {
        let ticket = create_mfa_ticket(&state.pool, subject.id, "passkey").await?;
        let (otp, _) = create_otp_code(&state.pool, subject.id, "mfa").await?;
        info!("mfa otp generated for subject {} ({}) code={}", subject.id, subject.subject_type, otp);
        return Ok(Json(AuthResponse::MfaRequired {
            ticket_id: ticket,
            otp_hint: "MFA enabled; enter OTP to finish sign-in.".to_string(),
        }));
    }

    let device_name = payload
        .device_name
        .unwrap_or_else(|| "Unknown Device".to_string());
    let device_fingerprint =
        resolve_device_fingerprint(payload.device_fingerprint.as_deref(), &device_name, &headers);

    let session = create_session(
        &state,
        &subject,
        "passkey",
        &device_name,
        &device_fingerprint,
        &headers,
    )
    .await?;

    Ok(Json(AuthResponse::Authenticated {
        token: session.token_plaintext.clone(),
        session: to_session_info(session.row, true),
        subject_id: subject.id,
        subject_type: subject.subject_type,
    }))
}

async fn verify_mfa(
    Path(subject): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<MfaVerifyRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let subject_kind = SubjectKind::from_str(&subject)?;

    let ticket: (Uuid, String, DateTime<Utc>, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT subject_id, primary_method, expires_at, used_at FROM mfa_tickets WHERE id = $1",
    )
    .bind(payload.ticket_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("invalid ticket"))?;

    if ticket.3.is_some() || ticket.2 < Utc::now() {
        return Err(AppError::unauthorized("ticket expired"));
    }

    let subject = load_subject_by_id(&state.pool, ticket.0).await?;
    if subject.subject_type != subject_kind.as_db_str() {
        return Err(AppError::unauthorized("subject mismatch"));
    }

    consume_otp_code(&state.pool, subject.id, "mfa", &payload.code).await?;

    sqlx::query("UPDATE mfa_tickets SET used_at = NOW() WHERE id = $1")
        .bind(payload.ticket_id)
        .execute(&state.pool)
        .await?;

    let device_name = payload
        .device_name
        .unwrap_or_else(|| "Unknown Device".to_string());
    let device_fingerprint =
        resolve_device_fingerprint(payload.device_fingerprint.as_deref(), &device_name, &headers);

    let auth_method = format!("{}+otp", ticket.1);
    let session = create_session(
        &state,
        &subject,
        &auth_method,
        &device_name,
        &device_fingerprint,
        &headers,
    )
    .await?;

    Ok(Json(AuthResponse::Authenticated {
        token: session.token_plaintext.clone(),
        session: to_session_info(session.row, true),
        subject_id: subject.id,
        subject_type: subject.subject_type,
    }))
}

async fn me_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SubjectProfile>, AppError> {
    let auth = parse_auth(&state, &headers).await?;
    let subject = load_subject_by_id(&state.pool, auth.subject_id).await?;
    Ok(Json(to_subject_profile(subject)))
}

async fn update_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateProfileRequest>,
) -> Result<Json<SubjectProfile>, AppError> {
    let auth = parse_auth(&state, &headers).await?;
    let next_name = payload.display_name.trim();
    if next_name.is_empty() {
        return Err(AppError::bad_request("display_name cannot be empty"));
    }

    sqlx::query(
        r#"
        INSERT INTO subject_profiles(subject_id, display_name)
        VALUES ($1, $2)
        ON CONFLICT (subject_id)
        DO UPDATE SET display_name = EXCLUDED.display_name, updated_at = NOW()
        "#,
    )
    .bind(auth.subject_id)
    .bind(next_name)
    .execute(&state.pool)
    .await?;

    let subject = load_subject_by_id(&state.pool, auth.subject_id).await?;
    Ok(Json(to_subject_profile(subject)))
}

async fn me_linked_subjects(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<LinkedSubject>>, AppError> {
    let auth = parse_auth(&state, &headers).await?;
    let current = load_subject_by_id(&state.pool, auth.subject_id).await?;
    let rows = load_subjects_by_person_id(&state.pool, current._person_id).await?;

    let linked = rows
        .into_iter()
        .map(|row| LinkedSubject {
            id: row.id,
            person_id: row._person_id,
            subject_type: row.subject_type,
            email: row.email,
            display_name: row.display_name,
            mfa_enabled: row.mfa_enabled,
            is_current: row.id == auth.subject_id,
        })
        .collect();
    Ok(Json(linked))
}

async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionInfo>>, AppError> {
    let auth = parse_auth(&state, &headers).await?;
    let rows: Vec<SessionRow> = sqlx::query_as(
        r#"
        SELECT id, auth_method, device_name, user_agent, ip, created_at, expires_at
        FROM sessions
        WHERE subject_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
        ORDER BY created_at DESC
        "#,
    )
    .bind(auth.subject_id)
    .fetch_all(&state.pool)
    .await?;

    let sessions = rows
        .into_iter()
        .map(|r| {
            let is_current = r.id == auth.session_id;
            to_session_info(r, is_current)
        })
        .collect();

    Ok(Json(sessions))
}

async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RevokeSessionRequest>,
) -> Result<Json<LogoutResponse>, AppError> {
    let auth = parse_auth(&state, &headers).await?;

    let result = sqlx::query(
        "UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND subject_id = $2 AND revoked_at IS NULL",
    )
    .bind(payload.session_id)
    .bind(auth.subject_id)
    .execute(&state.pool)
    .await?;

    Ok(Json(LogoutResponse {
        revoked: result.rows_affected() > 0,
    }))
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<LogoutResponse>, AppError> {
    let auth = parse_auth(&state, &headers).await?;

    let result = sqlx::query("UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL")
        .bind(auth.session_id)
        .execute(&state.pool)
        .await?;

    Ok(Json(LogoutResponse {
        revoked: result.rows_affected() > 0,
    }))
}

async fn parse_auth(state: &AppState, headers: &HeaderMap) -> Result<AuthContext, AppError> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::unauthorized("missing Authorization header"))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::unauthorized("invalid token format"))?
        .trim()
        .to_string();

    let token_hash = hash_session_token(&token, &state.session_token_pepper);
    let row: (Uuid, Uuid) = sqlx::query_as(
        r#"
        SELECT subject_id, id
        FROM sessions
        WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("session expired or invalid"))?;

    Ok(AuthContext {
        subject_id: row.0,
        session_id: row.1,
    })
}

async fn load_subject_by_email(
    pool: &PgPool,
    subject_kind: &SubjectKind,
    email: &str,
) -> Result<SubjectRow, AppError> {
    let normalized = email.trim().to_lowercase();
    let row: SubjectRow = sqlx::query_as(
        r#"
        SELECT s.id, s.person_id AS _person_id, s.subject_type, s.email, COALESCE(sp.display_name, s.display_name) AS display_name, s.mfa_enabled
        FROM subjects s
        LEFT JOIN subject_profiles sp ON sp.subject_id = s.id
        WHERE s.subject_type = $1 AND s.email = $2
        "#,
    )
    .bind(subject_kind.as_db_str())
    .bind(normalized)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::not_found("subject not found"))?;
    Ok(row)
}

async fn load_subject_by_id(pool: &PgPool, id: Uuid) -> Result<SubjectRow, AppError> {
    sqlx::query_as(
        r#"
        SELECT s.id, s.person_id AS _person_id, s.subject_type, s.email, COALESCE(sp.display_name, s.display_name) AS display_name, s.mfa_enabled
        FROM subjects s
        LEFT JOIN subject_profiles sp ON sp.subject_id = s.id
        WHERE s.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::not_found("subject not found"))
}

async fn load_subjects_by_person_id(pool: &PgPool, person_id: Uuid) -> Result<Vec<SubjectRow>, AppError> {
    let rows: Vec<SubjectRow> = sqlx::query_as(
        r#"
        SELECT s.id, s.person_id AS _person_id, s.subject_type, s.email, COALESCE(sp.display_name, s.display_name) AS display_name, s.mfa_enabled
        FROM subjects s
        LEFT JOIN subject_profiles sp ON sp.subject_id = s.id
        WHERE s.person_id = $1
        ORDER BY s.subject_type
        "#,
    )
    .bind(person_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

async fn create_otp_code(
    pool: &PgPool,
    subject_id: Uuid,
    purpose: &str,
) -> Result<(String, DateTime<Utc>), AppError> {
    let code = format!("{:06}", rand::thread_rng().gen_range(0..=999_999));
    let expires_at = Utc::now() + Duration::minutes(5);
    sqlx::query(
        "INSERT INTO otp_codes(id, subject_id, code, purpose, expires_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(subject_id)
    .bind(&code)
    .bind(purpose)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok((code, expires_at))
}

async fn consume_otp_code(
    pool: &PgPool,
    subject_id: Uuid,
    purpose: &str,
    code: &str,
) -> Result<(), AppError> {
    let otp_row: (Uuid, DateTime<Utc>, Option<DateTime<Utc>>) = sqlx::query_as(
        r#"
        SELECT id, expires_at, consumed_at
        FROM otp_codes
        WHERE subject_id = $1 AND purpose = $2 AND code = $3
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(subject_id)
    .bind(purpose)
    .bind(code)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("invalid otp"))?;

    if otp_row.2.is_some() {
        return Err(AppError::unauthorized("otp already used"));
    }

    if otp_row.1 < Utc::now() {
        return Err(AppError::unauthorized("otp expired"));
    }

    sqlx::query("UPDATE otp_codes SET consumed_at = NOW() WHERE id = $1")
        .bind(otp_row.0)
        .execute(pool)
        .await?;

    Ok(())
}

async fn create_mfa_ticket(
    pool: &PgPool,
    subject_id: Uuid,
    primary_method: &str,
) -> Result<Uuid, AppError> {
    let ticket_id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::minutes(10);

    sqlx::query(
        "INSERT INTO mfa_tickets(id, subject_id, primary_method, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(ticket_id)
    .bind(subject_id)
    .bind(primary_method)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(ticket_id)
}

async fn create_session(
    state: &AppState,
    subject: &SubjectRow,
    auth_method: &str,
    device_name: &str,
    device_fingerprint: &str,
    headers: &HeaderMap,
) -> Result<CreatedSession, AppError> {
    let token_plaintext = random_token(64);
    let token_hash = hash_session_token(&token_plaintext, &state.session_token_pepper);
    let expires_at = Utc::now() + Duration::hours(state.session_ttl_hours);

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let id = Uuid::new_v4();

    // Soft dedupe: keep only the latest active session per subject + device fingerprint.
    sqlx::query(
        r#"
        UPDATE sessions
        SET revoked_at = NOW()
        WHERE subject_id = $1
          AND device_fingerprint = $2
          AND revoked_at IS NULL
          AND expires_at > NOW()
        "#,
    )
    .bind(subject.id)
    .bind(device_fingerprint)
    .execute(&state.pool)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO sessions(
            id, subject_id, subject_type, auth_method, device_name, device_fingerprint, user_agent, ip, token_hash, token, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, $10)
        "#,
    )
    .bind(id)
    .bind(subject.id)
    .bind(&subject.subject_type)
    .bind(auth_method)
    .bind(device_name)
    .bind(device_fingerprint)
    .bind(user_agent)
    .bind(ip)
    .bind(&token_hash)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;

    let row: SessionRow = sqlx::query_as(
        "SELECT id, auth_method, device_name, user_agent, ip, created_at, expires_at FROM sessions WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;

    Ok(CreatedSession {
        row,
        token_plaintext,
    })
}

fn to_session_info(row: SessionRow, is_current: bool) -> SessionInfo {
    SessionInfo {
        id: row.id,
        auth_method: row.auth_method,
        device_name: row.device_name,
        user_agent: row.user_agent,
        ip: row.ip,
        created_at: row.created_at,
        expires_at: row.expires_at,
        is_current,
    }
}

fn to_subject_profile(row: SubjectRow) -> SubjectProfile {
    SubjectProfile {
        id: row.id,
        person_id: row._person_id,
        subject_type: row.subject_type,
        email: row.email,
        display_name: row.display_name,
        mfa_enabled: row.mfa_enabled,
    }
}

fn random_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn hash_session_token(token: &str, pepper: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pepper.as_bytes());
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

fn resolve_device_fingerprint(
    provided: Option<&str>,
    device_name: &str,
    headers: &HeaderMap,
) -> String {
    if let Some(value) = provided {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.chars().take(120).collect();
        }
    }

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown-ua");
    let seed = format!("{}|{}", device_name.trim().to_lowercase(), user_agent);
    seed.chars().take(120).collect()
}

fn hash_secret(raw: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(raw.as_bytes(), &salt)
        .map_err(|_| AppError::internal("hash failure"))?
        .to_string();
    Ok(hash)
}

fn verify_secret(hash: &str, raw: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(v) => v,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(raw.as_bytes(), &parsed)
        .is_ok()
}

fn map_webauthn_err(err: WebauthnError) -> AppError {
    warn!("webauthn error: {err}");
    AppError::unauthorized("webauthn ceremony failed")
}
