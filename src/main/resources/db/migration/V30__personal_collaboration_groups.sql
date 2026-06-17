ALTER TABLE iam_group
 MODIFY organization_id BINARY(16) NULL,
 ADD workspace_context VARCHAR(32) NOT NULL DEFAULT 'ORGANIZATION',
 ADD purge_after DATETIME(6) NULL,
 ADD deletion_requested_at DATETIME(6) NULL,
 ADD personal_creation_request_id BINARY(16) GENERATED ALWAYS AS(IF(workspace_context='INDIVIDUAL',creation_request_id,NULL)) STORED,
 ADD UNIQUE KEY uq_personal_group_creation(created_by_account_id,personal_creation_request_id),
 ADD UNIQUE KEY uq_group_context(id,workspace_context),
 DROP CHECK chk_group_status,
 ADD CONSTRAINT chk_group_status CHECK(status IN('ACTIVE','DISABLED','CLOSING')),
 ADD CONSTRAINT chk_group_context CHECK((workspace_context='ORGANIZATION' AND organization_id IS NOT NULL) OR
   (workspace_context='INDIVIDUAL' AND organization_id IS NULL AND parent_group_id IS NULL AND type='CUSTOM')),
 ADD CONSTRAINT chk_group_deletion CHECK((status='CLOSING' AND purge_after IS NOT NULL AND deletion_requested_at IS NOT NULL)
   OR (status<>'CLOSING' AND purge_after IS NULL AND deletion_requested_at IS NULL));
CREATE TABLE personal_group_member (
 group_id BINARY(16) NOT NULL,
 account_id BINARY(16) NOT NULL,
 id BINARY(16) NOT NULL,
 workspace_context VARCHAR(32) NOT NULL DEFAULT 'INDIVIDUAL',
 status VARCHAR(16) NOT NULL,
 version BIGINT NOT NULL,
 joined_at DATETIME(6) NOT NULL,
 revoked_at DATETIME(6) NULL,
 PRIMARY KEY(group_id,account_id),
 UNIQUE KEY uq_personal_member_id(id),
 CONSTRAINT fk_personal_member_context FOREIGN KEY(group_id,workspace_context) REFERENCES iam_group(id,workspace_context),
 CONSTRAINT fk_personal_member_account FOREIGN KEY(account_id) REFERENCES user_account(id),
 CONSTRAINT chk_personal_member_context CHECK(workspace_context='INDIVIDUAL'),
 CONSTRAINT chk_personal_member_status CHECK((status='ACTIVE' AND revoked_at IS NULL) OR(status='REVOKED' AND revoked_at IS NOT NULL)),
 CONSTRAINT chk_personal_member_version CHECK(version>=1),
 INDEX ix_personal_member_listing(account_id,status,group_id)
);
CREATE TABLE personal_group_invitation (
 id BINARY(16) NOT NULL PRIMARY KEY,
 group_id BINARY(16) NOT NULL,
 workspace_context VARCHAR(32) NOT NULL DEFAULT 'INDIVIDUAL',
 sender_account_id BINARY(16) NOT NULL,
 recipient_account_id BINARY(16) NOT NULL,
 status VARCHAR(16) NOT NULL,
 version BIGINT NOT NULL,
 creation_request_id BINARY(16) NOT NULL,
 created_at DATETIME(6) NOT NULL,
 expires_at DATETIME(6) NOT NULL,
 responded_at DATETIME(6) NULL,
 live_recipient BINARY(16) GENERATED ALWAYS AS(IF(status='PENDING',recipient_account_id,NULL)) STORED,
 UNIQUE KEY uq_personal_invitation_request(group_id,sender_account_id,creation_request_id),
 UNIQUE KEY uq_personal_invitation_pending(group_id,live_recipient),
 CONSTRAINT fk_personal_invitation_context FOREIGN KEY(group_id,workspace_context) REFERENCES iam_group(id,workspace_context),
 CONSTRAINT fk_personal_invitation_sender FOREIGN KEY(sender_account_id) REFERENCES user_account(id),
 CONSTRAINT fk_personal_invitation_recipient FOREIGN KEY(recipient_account_id) REFERENCES user_account(id),
 CONSTRAINT chk_personal_invitation_context CHECK(workspace_context='INDIVIDUAL'),
 CONSTRAINT chk_personal_invitation_status CHECK(status IN('PENDING','ACCEPTED','DECLINED','REVOKED')),
 CONSTRAINT chk_personal_invitation_version CHECK(version>=1),
 CONSTRAINT chk_personal_invitation_not_self CHECK(sender_account_id<>recipient_account_id),
 CONSTRAINT chk_personal_invitation_expiry CHECK(expires_at>created_at),
 INDEX ix_personal_invitation_inbox(recipient_account_id,status,id)
);
CREATE TABLE personal_group_audit (
 id BINARY(16) NOT NULL PRIMARY KEY,
 group_id BINARY(16) NOT NULL,
 account_id BINARY(16) NOT NULL,
 session_id BINARY(16) NOT NULL,
 event_type VARCHAR(64) NOT NULL,
 group_version BIGINT NOT NULL,
 occurred_at DATETIME(6) NOT NULL,
 INDEX ix_personal_group_audit(group_id,occurred_at,id)
);
