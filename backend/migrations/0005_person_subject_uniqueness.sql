CREATE UNIQUE INDEX IF NOT EXISTS idx_subjects_person_subject_type_unique
ON subjects(person_id, subject_type);
