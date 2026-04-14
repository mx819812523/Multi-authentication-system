ALTER TABLE sessions
ADD COLUMN IF NOT EXISTS device_fingerprint TEXT;

UPDATE sessions
SET device_fingerprint = COALESCE(NULLIF(device_name, ''), token)
WHERE device_fingerprint IS NULL;

ALTER TABLE sessions
ALTER COLUMN device_fingerprint SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_sessions_subject_device_active
ON sessions(subject_id, device_fingerprint)
WHERE revoked_at IS NULL;
