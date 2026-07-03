-- Creator is retained as an immutable audit identifier. Ownership points from account to organization.
ALTER TABLE organization DROP FOREIGN KEY fk_organization_creator;
ALTER TABLE user_account
    ADD COLUMN organization_id BINARY(16) NULL,
    ADD CONSTRAINT fk_account_organization FOREIGN KEY (organization_id) REFERENCES organization(id),
    ADD CONSTRAINT uq_human_organization_account UNIQUE (user_id, organization_id),
    DROP CHECK chk_account_type,
    ADD CONSTRAINT chk_account_type CHECK (
        (type = 'PERSONAL' AND organization_id IS NULL) OR
        (type IN ('COMPANY','UNIVERSITY','CUSTOM') AND organization_id IS NOT NULL));
ALTER TABLE login_identity DROP CHECK chk_login_identity_type,
    ADD CONSTRAINT chk_login_identity_type CHECK (type IN ('EMAIL','ACCOUNT_ID'));
ALTER TABLE account_group_member DROP CHECK chk_account_link_method,
    ADD CONSTRAINT chk_account_link_method CHECK (link_method IN ('REGISTRATION','PASSWORD','PIN','INVITATION'));
ALTER TABLE organization_invitation
    ADD COLUMN provisioning_account_id BINARY(16) NULL,
    ADD CONSTRAINT fk_invitation_provisioning_actor FOREIGN KEY (provisioning_account_id) REFERENCES user_account(id),
    ADD CONSTRAINT chk_invitation_provisioning CHECK (provisioning_account_id IS NULL OR status='ACCEPTED');
ALTER TABLE security_audit_event DROP CHECK chk_security_audit_type,
    ADD CONSTRAINT chk_security_audit_type CHECK (event_type IN (
        'REGISTRATION_COMPLETED', 'ACCOUNT_LINKED', 'LOGIN_SUCCEEDED', 'LOGIN_FAILED', 'SESSION_REVOKED', 'REFRESH_REPLAY',
        'ACCOUNT_UNLOCKED', 'ACCOUNT_UNLOCK_FAILED', 'ACCOUNT_UNLINKED', 'PIN_CHANGED', 'PREFERENCE_CHANGED',
        'ORGANIZATION_CREATED', 'ORGANIZATION_MEMBERSHIP_ACTIVATED', 'ORGANIZATION_INVITATION_CREATED',
        'ORGANIZATION_INVITATION_SUPERSEDED', 'ORGANIZATION_INVITATION_FAILED', 'ORGANIZATION_ACCOUNT_PROVISIONED'));
