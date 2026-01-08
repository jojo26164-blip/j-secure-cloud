-- Ajout colonne corbeille (soft delete)
ALTER TABLE files
ADD COLUMN deleted_at INTEGER;

-- Index pour lister rapidement fichiers actifs / corbeille
CREATE INDEX IF NOT EXISTS idx_files_user_deleted_at
ON files(user_id, deleted_at);
