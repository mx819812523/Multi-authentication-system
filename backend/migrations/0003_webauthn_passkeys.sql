ALTER TABLE passkey_credentials
ADD COLUMN IF NOT EXISTS credential_id TEXT,
ADD COLUMN IF NOT EXISTS passkey_json JSONB;

ALTER TABLE passkey_credentials
ALTER COLUMN token_hash DROP NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_passkey_credentials_unique
ON passkey_credentials(subject_id, credential_id)
WHERE credential_id IS NOT NULL;
