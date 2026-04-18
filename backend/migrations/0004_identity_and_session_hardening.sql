CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS persons (
  id UUID PRIMARY KEY,
  primary_email TEXT NOT NULL UNIQUE,
  phone TEXT UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE subjects
ADD COLUMN IF NOT EXISTS person_id UUID REFERENCES persons(id);

INSERT INTO persons(id, primary_email)
SELECT gen_random_uuid(), lower(trim(s.email))
FROM subjects s
LEFT JOIN persons p ON p.primary_email = lower(trim(s.email))
WHERE p.id IS NULL;

UPDATE subjects s
SET person_id = p.id
FROM persons p
WHERE p.primary_email = lower(trim(s.email))
  AND s.person_id IS NULL;

ALTER TABLE subjects
ALTER COLUMN person_id SET NOT NULL;

CREATE TABLE IF NOT EXISTS subject_profiles (
  subject_id UUID PRIMARY KEY REFERENCES subjects(id) ON DELETE CASCADE,
  display_name TEXT NOT NULL,
  avatar_url TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO subject_profiles(subject_id, display_name)
SELECT s.id, s.display_name
FROM subjects s
LEFT JOIN subject_profiles sp ON sp.subject_id = s.id
WHERE sp.subject_id IS NULL;

ALTER TABLE sessions
ADD COLUMN IF NOT EXISTS token_hash TEXT;

UPDATE sessions
SET token_hash = token
WHERE token_hash IS NULL;

ALTER TABLE sessions
ALTER COLUMN token_hash SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_token_hash_unique
ON sessions(token_hash);

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.table_constraints
    WHERE table_name = 'sessions' AND constraint_name = 'sessions_token_key'
  ) THEN
    ALTER TABLE sessions DROP CONSTRAINT sessions_token_key;
  END IF;
END $$;

ALTER TABLE sessions
ALTER COLUMN token DROP NOT NULL;

UPDATE sessions SET token = NULL;
