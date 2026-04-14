export type SubjectType = 'member' | 'community_staff' | 'platform_staff'

export type SubjectProfile = {
  id: string
  subject_type: SubjectType
  email: string
  display_name: string
  mfa_enabled: boolean
}

export type SessionInfo = {
  id: string
  auth_method: string
  device_name: string
  user_agent?: string
  ip?: string
  created_at: string
  expires_at: string
  is_current: boolean
}

export type AuthResponse =
  | {
      status: 'authenticated'
      token: string
      subject: SubjectProfile
      session: SessionInfo
    }
  | {
      status: 'mfa_required'
      ticket_id: string
      otp_hint: string
      demo_otp: string
    }

export type PasskeyCeremonyResponse = {
  ceremony_id: string
  options: Record<string, unknown>
}

const base = '/api'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${base}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {})
    }
  })

  if (!res.ok) {
    const text = await res.text()
    let parsed = text
    try {
      const json = JSON.parse(text)
      parsed = json.error ?? text
    } catch {
      // no-op
    }
    throw new Error(parsed || `HTTP ${res.status}`)
  }

  return (await res.json()) as T
}

export const api = {
  passwordLogin(
    subject: SubjectType,
    payload: { email: string; password: string; device_name?: string; device_fingerprint?: string }
  ) {
    return request<AuthResponse>(`/auth/${subject}/password/login`, {
      method: 'POST',
      body: JSON.stringify(payload)
    })
  },
  otpRequest(subject: SubjectType, payload: { email: string }) {
    return request<{ otp_hint: string; demo_otp: string; expires_in_sec: number }>(`/auth/${subject}/otp/request`, {
      method: 'POST',
      body: JSON.stringify(payload)
    })
  },
  otpVerify(
    subject: SubjectType,
    payload: { email: string; code: string; device_name?: string; device_fingerprint?: string }
  ) {
    return request<AuthResponse>(`/auth/${subject}/otp/verify`, {
      method: 'POST',
      body: JSON.stringify(payload)
    })
  },
  passkeyRegisterStart(subject: SubjectType, payload: { email: string; passkey_name?: string }) {
    return request<PasskeyCeremonyResponse>(`/auth/${subject}/passkey/register/start`, {
      method: 'POST',
      body: JSON.stringify(payload)
    })
  },
  passkeyRegisterFinish(subject: SubjectType, payload: { email: string; ceremony_id: string; credential: unknown }) {
    return request<{ revoked: boolean }>(`/auth/${subject}/passkey/register/finish`, {
      method: 'POST',
      body: JSON.stringify(payload)
    })
  },
  passkeyLoginStart(subject: SubjectType, payload: { email: string }) {
    return request<PasskeyCeremonyResponse>(`/auth/${subject}/passkey/login/start`, {
      method: 'POST',
      body: JSON.stringify(payload)
    })
  },
  passkeyLoginFinish(
    subject: SubjectType,
    payload: {
      email: string
      ceremony_id: string
      credential: unknown
      device_name?: string
      device_fingerprint?: string
    }
  ) {
    return request<AuthResponse>(`/auth/${subject}/passkey/login/finish`, {
      method: 'POST',
      body: JSON.stringify(payload)
    })
  },
  verifyMfa(
    subject: SubjectType,
    payload: { ticket_id: string; code: string; device_name?: string; device_fingerprint?: string }
  ) {
    return request<AuthResponse>(`/auth/${subject}/mfa/verify`, {
      method: 'POST',
      body: JSON.stringify(payload)
    })
  },
  profile(token: string) {
    return request<SubjectProfile>(`/me/profile`, {
      headers: { Authorization: `Bearer ${token}` }
    })
  },
  sessions(token: string) {
    return request<SessionInfo[]>(`/me/sessions`, {
      headers: { Authorization: `Bearer ${token}` }
    })
  },
  revoke(token: string, session_id: string) {
    return request<{ revoked: boolean }>(`/me/sessions/revoke`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify({ session_id })
    })
  },
  logout(token: string) {
    return request<{ revoked: boolean }>(`/auth/logout`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` }
    })
  }
}
