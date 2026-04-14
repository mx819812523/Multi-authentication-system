import { AnimatePresence, motion } from 'framer-motion'
import { FormEvent, useEffect, useMemo, useState } from 'react'
import { api, AuthResponse, SessionInfo, SubjectProfile, SubjectType } from './lib/api'
import { createPasskeyCredential, getPasskeyCredential } from './lib/webauthn'

type Method = 'password' | 'otp' | 'passkey'

const SUBJECTS: Array<{ key: SubjectType; label: string; hint: string; defaultEmail: string }> = [
  { key: 'member', label: 'Member', hint: '会员', defaultEmail: 'member@demo.local' },
  { key: 'community_staff', label: 'Community Staff', hint: '社区运营', defaultEmail: 'community@demo.local' },
  { key: 'platform_staff', label: 'Platform Staff', hint: '平台运营', defaultEmail: 'platform@demo.local' }
]

const PASSWORD_HINT: Record<SubjectType, string> = {
  member: 'Member#123',
  community_staff: 'Community#123',
  platform_staff: 'Platform#123'
}

const STORAGE = {
  token(subject: SubjectType) {
    return `msa_token_${subject}`
  }
}

function buildDeviceFingerprint(subject: SubjectType, email: string, deviceName: string): string {
  const ua = typeof navigator !== 'undefined' ? navigator.userAgent : 'unknown-ua'
  return `${subject}|${email.trim().toLowerCase()}|${deviceName.trim().toLowerCase()}|${ua}`.slice(0, 120)
}

export default function App() {
  const [subject, setSubject] = useState<SubjectType>('member')
  const [method, setMethod] = useState<Method>('password')

  const defaultEmail = useMemo(() => SUBJECTS.find((s) => s.key === subject)?.defaultEmail ?? '', [subject])
  const [email, setEmail] = useState(defaultEmail)
  const [password, setPassword] = useState(PASSWORD_HINT.member)
  const [deviceName, setDeviceName] = useState('MacBook Pro')

  const [otpCode, setOtpCode] = useState('')
  const [otpPreview, setOtpPreview] = useState('')
  const [otpHint, setOtpHint] = useState('')

  const [passkeyName, setPasskeyName] = useState('Primary Device')

  const [mfaTicket, setMfaTicket] = useState<string | null>(null)
  const [mfaOtp, setMfaOtp] = useState('')
  const [mfaPreview, setMfaPreview] = useState('')

  const [token, setToken] = useState<string | null>(localStorage.getItem(STORAGE.token(subject)))
  const [profile, setProfile] = useState<SubjectProfile | null>(null)
  const [sessions, setSessions] = useState<SessionInfo[]>([])

  const [message, setMessage] = useState<string>('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setEmail(defaultEmail)
    setPassword(PASSWORD_HINT[subject])
    const storedToken = localStorage.getItem(STORAGE.token(subject))
    setToken(storedToken)
    setMethod('password')
    resetFlow()
  }, [defaultEmail, subject])

  useEffect(() => {
    if (!token) {
      setProfile(null)
      setSessions([])
      return
    }

    void refreshProfile(token)
    void refreshSessions(token)
  }, [token])

  function resetFlow() {
    setOtpCode('')
    setOtpPreview('')
    setOtpHint('')
    setMfaTicket(null)
    setMfaOtp('')
    setMfaPreview('')
    setMessage('')
  }

  async function refreshProfile(currentToken: string) {
    try {
      const data = await api.profile(currentToken)
      setProfile(data)
    } catch {
      clearLoginState()
    }
  }

  async function refreshSessions(currentToken: string) {
    try {
      const list = await api.sessions(currentToken)
      setSessions(list)
    } catch {
      clearLoginState()
    }
  }

  function clearLoginState() {
    localStorage.removeItem(STORAGE.token(subject))
    setToken(null)
    setProfile(null)
    setSessions([])
  }

  function applyAuthResult(result: AuthResponse) {
    if (result.status === 'mfa_required') {
      setMfaTicket(result.ticket_id)
      setMfaPreview(result.demo_otp)
      setMessage(`${result.otp_hint} demo OTP: ${result.demo_otp}`)
      return
    }

    localStorage.setItem(STORAGE.token(subject), result.token)
    setToken(result.token)
    setProfile(result.subject)
    setSessions((prev) => [result.session, ...prev.filter((s) => s.id !== result.session.id)])
    setMessage(`登录成功: ${result.subject.display_name}`)
    setMfaTicket(null)
  }

  async function onPasswordLogin(e: FormEvent) {
    e.preventDefault()
    setLoading(true)
    setMessage('')
    try {
      const result = await api.passwordLogin(subject, {
        email,
        password,
        device_name: deviceName,
        device_fingerprint: buildDeviceFingerprint(subject, email, deviceName)
      })
      applyAuthResult(result)
    } catch (err) {
      setMessage((err as Error).message)
    } finally {
      setLoading(false)
    }
  }

  async function onRequestOtp() {
    setLoading(true)
    setMessage('')
    try {
      const res = await api.otpRequest(subject, { email })
      setOtpHint(res.otp_hint)
      setOtpPreview(res.demo_otp)
      setMessage(`${res.otp_hint} demo OTP: ${res.demo_otp}`)
    } catch (err) {
      setMessage((err as Error).message)
    } finally {
      setLoading(false)
    }
  }

  async function onVerifyOtp(e: FormEvent) {
    e.preventDefault()
    setLoading(true)
    setMessage('')
    try {
      const result = await api.otpVerify(subject, {
        email,
        code: otpCode,
        device_name: deviceName,
        device_fingerprint: buildDeviceFingerprint(subject, email, deviceName)
      })
      applyAuthResult(result)
    } catch (err) {
      setMessage((err as Error).message)
    } finally {
      setLoading(false)
    }
  }

  async function onEnrollPasskey() {
    setLoading(true)
    setMessage('')
    try {
      const start = await api.passkeyRegisterStart(subject, {
        email,
        passkey_name: passkeyName
      })

      const credential = await createPasskeyCredential(start.options)
      await api.passkeyRegisterFinish(subject, {
        email,
        ceremony_id: start.ceremony_id,
        credential
      })
      setMessage('Passkey enrolled successfully. You can now login with passkey.')
    } catch (err) {
      setMessage((err as Error).message)
    } finally {
      setLoading(false)
    }
  }

  async function onPasskeyLogin(e: FormEvent) {
    e.preventDefault()
    setLoading(true)
    setMessage('')
    try {
      const start = await api.passkeyLoginStart(subject, { email })
      const credential = await getPasskeyCredential(start.options)
      const result = await api.passkeyLoginFinish(subject, {
        email,
        ceremony_id: start.ceremony_id,
        credential,
        device_name: deviceName,
        device_fingerprint: buildDeviceFingerprint(subject, email, deviceName)
      })
      applyAuthResult(result)
    } catch (err) {
      setMessage((err as Error).message)
    } finally {
      setLoading(false)
    }
  }

  async function onVerifyMfa(e: FormEvent) {
    e.preventDefault()
    if (!mfaTicket) return

    setLoading(true)
    setMessage('')
    try {
      const result = await api.verifyMfa(subject, {
        ticket_id: mfaTicket,
        code: mfaOtp,
        device_name: deviceName,
        device_fingerprint: buildDeviceFingerprint(subject, email, deviceName)
      })
      applyAuthResult(result)
    } catch (err) {
      setMessage((err as Error).message)
    } finally {
      setLoading(false)
    }
  }

  async function onRevokeSession(sessionId: string) {
    if (!token) return

    setLoading(true)
    try {
      await api.revoke(token, sessionId)
      await refreshSessions(token)
      setMessage('session revoked')
    } catch (err) {
      setMessage((err as Error).message)
    } finally {
      setLoading(false)
    }
  }

  async function onLogout() {
    if (!token) return
    setLoading(true)
    try {
      await api.logout(token)
      clearLoginState()
      setMessage('logged out')
    } catch (err) {
      setMessage((err as Error).message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="app-shell">
      <div className="bg-grid" />
      <header className="hero">
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.55 }}
          className="eyebrow"
        >
          Multi-Subject Authentication
        </motion.p>
        <motion.h1
          initial={{ opacity: 0, y: 28 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.06 }}
        >
          One Platform, Three Subject Realms.
        </motion.h1>
        <motion.p
          className="lead"
          initial={{ opacity: 0, y: 26 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.12 }}
        >
          Password, OTP, Passkey and optional MFA with concurrent multi-device sessions.
        </motion.p>
      </header>

      <main className="workspace">
        <section className="lane">
          <div className="subject-switch" role="tablist" aria-label="subject switch">
            {SUBJECTS.map((s) => {
              const active = subject === s.key
              return (
                <button key={s.key} className={active ? 'active' : ''} onClick={() => setSubject(s.key)}>
                  <span>{s.label}</span>
                  <small>{s.hint}</small>
                  {active && <motion.div layoutId="active-subject" className="active-bar" />}
                </button>
              )
            })}
          </div>

          <div className="inputs-row">
            <label>
              Email
              <input value={email} onChange={(e) => setEmail(e.target.value)} />
            </label>
            <label>
              Device
              <input value={deviceName} onChange={(e) => setDeviceName(e.target.value)} />
            </label>
          </div>

          <div className="method-switch">
            {(['password', 'otp', 'passkey'] as Method[]).map((m) => (
              <button key={m} onClick={() => setMethod(m)} className={method === m ? 'active' : ''}>
                {m.toUpperCase()}
              </button>
            ))}
          </div>

          <AnimatePresence mode="wait">
            {method === 'password' && (
              <motion.form
                key="password"
                className="flow"
                onSubmit={onPasswordLogin}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 16 }}
              >
                <label>
                  Password
                  <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
                </label>
                <p className="tip">Demo password: {PASSWORD_HINT[subject]}</p>
                <button disabled={loading} type="submit">
                  Continue with Password
                </button>
              </motion.form>
            )}

            {method === 'otp' && (
              <motion.form
                key="otp"
                className="flow"
                onSubmit={onVerifyOtp}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 16 }}
              >
                <div className="inline-actions">
                  <button type="button" disabled={loading} onClick={onRequestOtp}>
                    Request OTP
                  </button>
                  {otpPreview && <span className="code">{otpPreview}</span>}
                </div>
                <label>
                  OTP Code
                  <input value={otpCode} onChange={(e) => setOtpCode(e.target.value)} />
                </label>
                <p className="tip">{otpHint || 'Request an OTP first.'}</p>
                <button disabled={loading} type="submit">
                  Continue with OTP
                </button>
              </motion.form>
            )}

            {method === 'passkey' && (
              <motion.div
                key="passkey"
                className="flow"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 16 }}
              >
                <div className="split">
                  <label>
                    Passkey Name
                    <input value={passkeyName} onChange={(e) => setPasskeyName(e.target.value)} />
                  </label>
                  <button type="button" disabled={loading} onClick={onEnrollPasskey}>
                    Enroll Passkey
                  </button>
                </div>
                <form onSubmit={onPasskeyLogin} className="subflow">
                  <p className="tip">Use browser/native passkey prompt for sign-in.</p>
                  <button disabled={loading} type="submit">
                    Continue with Passkey
                  </button>
                </form>
              </motion.div>
            )}
          </AnimatePresence>

          {mfaTicket && (
            <motion.form
              className="mfa"
              onSubmit={onVerifyMfa}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <h3>MFA Required</h3>
              <label>
                OTP
                <input value={mfaOtp} onChange={(e) => setMfaOtp(e.target.value)} />
              </label>
              {mfaPreview && <p className="tip">Demo MFA OTP: {mfaPreview}</p>}
              <button type="submit" disabled={loading}>
                Verify MFA
              </button>
            </motion.form>
          )}

          {message && <p className="notice">{message}</p>}
        </section>

        <section className="lane sessions">
          <div className="sessions-head">
            <h2>Active Sessions</h2>
            <button disabled={!token || loading} onClick={onLogout}>
              Logout Current
            </button>
          </div>

          {!profile && <p className="tip">Sign in to inspect multi-device sessions.</p>}

          {profile && (
            <div className="profile">
              <p>{profile.display_name}</p>
              <small>
                {profile.email} · {profile.subject_type}
              </small>
            </div>
          )}

          <div className="session-list">
            {sessions.map((s, index) => (
              <motion.article
                key={s.id}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.03 }}
                className="session-item"
              >
                <div>
                  <p>
                    {s.device_name} {s.is_current ? '(Current)' : ''}
                  </p>
                  <small>
                    {s.auth_method} · {new Date(s.created_at).toLocaleString()}
                  </small>
                </div>
                <button disabled={loading || s.is_current} onClick={() => onRevokeSession(s.id)}>
                  Revoke
                </button>
              </motion.article>
            ))}
          </div>
        </section>
      </main>
    </div>
  )
}
