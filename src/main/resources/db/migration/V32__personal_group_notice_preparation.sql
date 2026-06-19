-- Existing captured deadlines are preserved. Only new closures wait for owning-service durable notices.
ALTER TABLE iam_group
    ADD deletion_notice_seconds BIGINT NOT NULL DEFAULT 604800,
    ADD deletion_notice_batch_id BINARY(16) NULL,
    DROP CHECK chk_group_status,
    DROP CHECK chk_group_deletion,
    ADD CONSTRAINT chk_group_status CHECK(status IN ('ACTIVE','DISABLED','PREPARING','CLOSING')),
    ADD CONSTRAINT chk_group_context_status CHECK(workspace_context='INDIVIDUAL' OR status IN ('ACTIVE','DISABLED')),
    ADD CONSTRAINT chk_group_notice_seconds CHECK(deletion_notice_seconds BETWEEN 2 AND 604800),
    ADD CONSTRAINT chk_group_deletion CHECK(
        (status='PREPARING' AND purge_after IS NULL AND deletion_requested_at IS NOT NULL AND deletion_notice_batch_id IS NULL)
        OR (status='CLOSING' AND purge_after IS NOT NULL AND deletion_requested_at IS NOT NULL)
        OR (status IN ('ACTIVE','DISABLED') AND purge_after IS NULL AND deletion_requested_at IS NULL AND deletion_notice_batch_id IS NULL)
    );

INSERT INTO iam_authority VALUES (UUID_TO_BIN('ebcd4171-1872-5e96-b007-7012bda5a247'), 'auth-service', 'group.delete.cancel', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('23f631f1-edf1-5bfe-b790-e5073b0a5b51'), 'auth-service', 'group.delete.cancel', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('9e7fe7b9-0282-515f-8e8b-e3a9377c58d4'), UUID_TO_BIN('23f631f1-edf1-5bfe-b790-e5073b0a5b51'), 'auth-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('9e7fe7b9-0282-515f-8e8b-e3a9377c58d4'), 'auth-service', UUID_TO_BIN('ebcd4171-1872-5e96-b007-7012bda5a247'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('395893c4-f238-57fe-861d-2592289a6b6e'), UUID_TO_BIN('ebcd4171-1872-5e96-b007-7012bda5a247'));
INSERT INTO iam_role_authority SELECT id,UUID_TO_BIN('ebcd4171-1872-5e96-b007-7012bda5a247') FROM iam_role WHERE role_key='BASIC_CAPABILITIES';
UPDATE iam_role SET version=version+1,updated_at=UTC_TIMESTAMP(6) WHERE role_key IN ('BASIC_CAPABILITIES','BASIC_GROUP_OWNER');
UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL';
