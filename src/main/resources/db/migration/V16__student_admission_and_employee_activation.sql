ALTER TABLE organization_membership MODIFY official_email VARCHAR(254) NULL;
CREATE TABLE employee_activation (
 account_id BINARY(16) NOT NULL PRIMARY KEY, organization_id BINARY(16) NOT NULL,
 username VARCHAR(100) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 status VARCHAR(32) NOT NULL, attempts INT NOT NULL DEFAULT 0,
 created_by BINARY(16) NOT NULL, request_id BINARY(16) NOT NULL, created_at DATETIME(6) NOT NULL,
 CONSTRAINT fk_employee_account FOREIGN KEY(account_id) REFERENCES user_account(id),
 CONSTRAINT fk_employee_org FOREIGN KEY(organization_id) REFERENCES organization(id),
 CONSTRAINT uq_employee_username UNIQUE(username), CONSTRAINT uq_employee_request UNIQUE(organization_id,created_by,request_id),
 CONSTRAINT chk_employee_status CHECK(status IN('PENDING','ACTIVATED')), CONSTRAINT chk_employee_attempts CHECK(attempts BETWEEN 0 AND 5)
);
ALTER TABLE security_audit_event DROP CHECK chk_security_audit_type,
 ADD CONSTRAINT chk_security_audit_type CHECK(event_type IN(
 'REGISTRATION_COMPLETED','ACCOUNT_LINKED','LOGIN_SUCCEEDED','LOGIN_FAILED','SESSION_REVOKED','REFRESH_REPLAY',
 'ACCOUNT_UNLOCKED','ACCOUNT_UNLOCK_FAILED','ACCOUNT_UNLINKED','PIN_CHANGED','PREFERENCE_CHANGED',
 'ORGANIZATION_CREATED','ORGANIZATION_MEMBERSHIP_ACTIVATED','ORGANIZATION_INVITATION_CREATED',
 'ORGANIZATION_INVITATION_SUPERSEDED','ORGANIZATION_INVITATION_FAILED','ORGANIZATION_ACCOUNT_PROVISIONED','GROUP_CREATED',
 'ACCOUNT_REMOVAL_REQUESTED','ACCOUNT_REMOVAL_REJECTED','ACCOUNT_SOFT_DELETED','ACCOUNT_RESTORED','ACCOUNT_PURGED',
 'ORGANIZATION_MEMBER_REMOVED','ORGANIZATION_MEMBER_BLACKLISTED','ORGANIZATION_MEMBER_RESTORED','ACCOUNT_RECOVERY_FAILED',
 'GROUP_MEMBER_ASSIGNED','GROUP_MEMBER_REVOKED','GROUP_JOIN_REQUESTED','GROUP_JOIN_APPROVED','GROUP_JOIN_REJECTED','GROUP_JOIN_CANCELLED',
 'GROUP_RULE_CHANGED','GROUP_MEMBER_ADMIN_CHANGED','ACADEMIC_SEMESTER_CREATED','COURSE_ENROLLMENT_REPLACED',
 'GROUP_INVITATION_CREATED','GROUP_INVITATION_ACCEPTED','GROUP_INVITATION_REVOKED','EMPLOYEE_PROVISIONED','EMPLOYEE_ACTIVATED','EMPLOYEE_CREDENTIAL_RESET','STUDENT_ADMISSION_CREATED','STUDENT_ADMISSION_VERIFIED','STUDENT_ADMISSION_APPROVED','STUDENT_ADMISSION_REJECTED','INSTITUTE_CURATOR_CHANGED','INSTITUTE_DOMAIN_CHANGED'));

CREATE TABLE institute_email_domain (
 organization_id BINARY(16) NOT NULL, domain VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 PRIMARY KEY(organization_id,domain), CONSTRAINT fk_student_domain_org FOREIGN KEY(organization_id) REFERENCES organization(id)
);
ALTER TABLE organization_membership ADD CONSTRAINT uq_org_member_curator_scope UNIQUE(organization_id,id);
CREATE TABLE institute_curator (
 organization_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL, PRIMARY KEY(organization_id,membership_id),
 CONSTRAINT fk_curator_scope FOREIGN KEY(organization_id,membership_id) REFERENCES organization_membership(organization_id,id)
);
CREATE TABLE student_admission (
 id BINARY(16) NOT NULL PRIMARY KEY, organization_id BINARY(16) NOT NULL,
 applicant_account_id BINARY(16) NOT NULL, applicant_user_id BINARY(16) NOT NULL, account_group_id BINARY(16) NOT NULL,
 email VARCHAR(254) NOT NULL, method VARCHAR(32) NOT NULL, status VARCHAR(32) NOT NULL,
 password_hash VARCHAR(255) NOT NULL, code_hash VARCHAR(64) NOT NULL, code_expires_at DATETIME(6) NOT NULL,
 attempts INT NOT NULL DEFAULT 0, version BIGINT NOT NULL DEFAULT 1, evidence_key VARCHAR(512) NULL,
 evidence_type VARCHAR(64) NULL, reviewed_by BINARY(16) NULL, review_reason VARCHAR(500) NULL,
 student_account_id BINARY(16) NULL, membership_id BINARY(16) NULL, created_at DATETIME(6) NOT NULL,
 pending_account_id BINARY(16) GENERATED ALWAYS AS(IF(status IN('EMAIL_PENDING','PENDING_REVIEW'),applicant_account_id,NULL)) STORED,
 CONSTRAINT uq_student_pending UNIQUE(organization_id,pending_account_id),
 CONSTRAINT fk_admission_institute FOREIGN KEY(organization_id) REFERENCES organization(id),
 CONSTRAINT fk_admission_applicant FOREIGN KEY(applicant_account_id) REFERENCES user_account(id),
 CONSTRAINT chk_admission_method CHECK(method IN('INSTITUTE_EMAIL','DOCUMENT')),
 CONSTRAINT chk_admission_status CHECK(status IN('EMAIL_PENDING','PENDING_REVIEW','APPROVED','REJECTED','EXPIRED','FAILED')),
 CONSTRAINT chk_admission_attempts CHECK(attempts BETWEEN 0 AND 5), CONSTRAINT chk_admission_version CHECK(version>=1),
 CONSTRAINT chk_admission_evidence CHECK((method='DOCUMENT' AND evidence_key IS NOT NULL AND evidence_type IS NOT NULL) OR(method='INSTITUTE_EMAIL' AND evidence_key IS NULL AND evidence_type IS NULL)),
 INDEX ix_admission_review(organization_id,status,id), INDEX ix_admission_applicant(applicant_account_id,id)
);

CREATE TABLE admission_evidence_deletion (
 object_key VARCHAR(512) NOT NULL PRIMARY KEY, attempts INT NOT NULL DEFAULT 0, available_at DATETIME(6) NOT NULL,
 CONSTRAINT chk_evidence_delete_attempts CHECK(attempts>=0), INDEX ix_evidence_delete(available_at)
);
