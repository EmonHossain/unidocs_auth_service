-- Lifecycle maintenance has no human session; retain its explicit absent-session evidence.
ALTER TABLE personal_group_audit MODIFY session_id BINARY(16) NULL;
