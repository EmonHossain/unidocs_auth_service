CREATE TABLE academic_semester (
 id BINARY(16) NOT NULL PRIMARY KEY, organization_id BINARY(16) NOT NULL,
 code VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 starts_at DATETIME(6) NOT NULL, ends_at DATETIME(6) NOT NULL,
 CONSTRAINT fk_semester_organization FOREIGN KEY(organization_id) REFERENCES organization(id),
 CONSTRAINT uq_semester_code UNIQUE(organization_id,code),
 CONSTRAINT uq_semester_scope UNIQUE(organization_id,id),
 CONSTRAINT chk_semester_window CHECK(ends_at>starts_at), INDEX ix_semester_listing(organization_id,id)
);
CREATE TABLE group_rule (
 group_id BINARY(16) NOT NULL PRIMARY KEY, organization_id BINARY(16) NOT NULL,
 discovery_scope VARCHAR(32) NOT NULL, join_rule VARCHAR(32) NOT NULL,
 department_group_id BINARY(16) NULL, semester_id BINARY(16) NULL, version BIGINT NOT NULL,
 CONSTRAINT fk_group_rule_group FOREIGN KEY(organization_id,group_id) REFERENCES iam_group(organization_id,id),
 CONSTRAINT fk_group_rule_department FOREIGN KEY(organization_id,department_group_id) REFERENCES iam_group(organization_id,id),
 CONSTRAINT fk_group_rule_semester FOREIGN KEY(organization_id,semester_id) REFERENCES academic_semester(organization_id,id),
 CONSTRAINT chk_group_rule_scope CHECK(discovery_scope IN('ORGANIZATION','DEPARTMENT','INVITATION_ONLY')),
 CONSTRAINT chk_group_rule_join CHECK(join_rule IN('OPEN','APPROVAL','INVITATION_ONLY','COURSE_ENROLLMENT')),
 CONSTRAINT chk_group_rule_department CHECK((discovery_scope='DEPARTMENT' AND department_group_id IS NOT NULL AND department_group_id<>group_id) OR (discovery_scope<>'DEPARTMENT' AND department_group_id IS NULL)),
 CONSTRAINT chk_group_rule_version CHECK(version>=1)
);
INSERT INTO group_rule(group_id,organization_id,discovery_scope,join_rule,version)
 SELECT g.id,g.organization_id,'ORGANIZATION',IF(o.type='UNIVERSITY' AND g.type='COURSE','COURSE_ENROLLMENT','APPROVAL'),1
 FROM iam_group g JOIN organization o ON o.id=g.organization_id;
CREATE TABLE student_enrollment (
 id BINARY(16) NOT NULL PRIMARY KEY, organization_id BINARY(16) NOT NULL,
 account_id BINARY(16) NOT NULL, organization_membership_id BINARY(16) NOT NULL,
 semester_id BINARY(16) NOT NULL, version BIGINT NOT NULL,
 updated_by BINARY(16) NOT NULL, last_request_id BINARY(16) NOT NULL,
 last_fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, updated_at DATETIME(6) NOT NULL,
 CONSTRAINT fk_student_enrollment_anchor FOREIGN KEY(organization_id,organization_membership_id,account_id) REFERENCES organization_membership(organization_id,id,account_id),
 CONSTRAINT fk_student_enrollment_semester FOREIGN KEY(organization_id,semester_id) REFERENCES academic_semester(organization_id,id),
 CONSTRAINT uq_student_enrollment_anchor UNIQUE(organization_membership_id),
 CONSTRAINT uq_student_enrollment_source UNIQUE(organization_id,account_id,organization_membership_id,id),
 CONSTRAINT chk_student_enrollment_version CHECK(version>=1)
);
CREATE TABLE group_invitation (
 id BINARY(16) NOT NULL PRIMARY KEY, organization_id BINARY(16) NOT NULL,
 group_id BINARY(16) NOT NULL, account_id BINARY(16) NOT NULL, organization_membership_id BINARY(16) NOT NULL,
 issued_by BINARY(16) NOT NULL, request_id BINARY(16) NOT NULL,
 fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 role VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 valid_from DATETIME(6) NOT NULL, valid_until DATETIME(6) NULL, expires_at DATETIME(6) NOT NULL,
 status VARCHAR(32) NOT NULL, version BIGINT NOT NULL, membership_id BINARY(16) NULL,
 created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
 pending_anchor_id BINARY(16) GENERATED ALWAYS AS(IF(status='PENDING',organization_membership_id,NULL)) STORED,
 CONSTRAINT fk_group_invite_group FOREIGN KEY(organization_id,group_id) REFERENCES iam_group(organization_id,id),
 CONSTRAINT fk_group_invite_anchor FOREIGN KEY(organization_id,organization_membership_id,account_id) REFERENCES organization_membership(organization_id,id,account_id),
 CONSTRAINT uq_group_invite_retry UNIQUE(organization_id,issued_by,request_id),
 CONSTRAINT uq_group_invite_pending UNIQUE(group_id,pending_anchor_id),
 CONSTRAINT uq_group_invite_source UNIQUE(organization_id,group_id,account_id,organization_membership_id,id),
 CONSTRAINT chk_group_invite_status CHECK(status IN('PENDING','ACCEPTED','REVOKED')),
 CONSTRAINT chk_group_invite_version CHECK(version>=1),
 CONSTRAINT chk_group_invite_window CHECK(valid_until IS NULL OR valid_until>valid_from),
 CONSTRAINT chk_group_invite_accept CHECK((status='ACCEPTED' AND membership_id IS NOT NULL) OR (status<>'ACCEPTED' AND membership_id IS NULL)),
 INDEX ix_group_invite_owner(organization_id,account_id,id)
);
ALTER TABLE group_membership
 ADD can_manage_group BOOLEAN NOT NULL DEFAULT FALSE,
 ADD source_enrollment_id BINARY(16) NULL,
 ADD enrollment_version BIGINT NULL,
 ADD source_invitation_id BINARY(16) NULL,
 DROP CHECK chk_group_member_source,
 ADD CONSTRAINT chk_group_member_source CHECK(
  (source IN('ORGANIZATION_ASSIGNMENT','OPEN_JOIN') AND source_request_id IS NULL AND source_enrollment_id IS NULL AND enrollment_version IS NULL AND source_invitation_id IS NULL) OR
  (source='ADMIN_APPROVAL' AND source_request_id IS NOT NULL AND source_enrollment_id IS NULL AND enrollment_version IS NULL AND source_invitation_id IS NULL) OR
  (source='COURSE_ENROLLMENT' AND source_request_id IS NULL AND source_enrollment_id IS NOT NULL AND enrollment_version IS NOT NULL AND enrollment_version>=1 AND source_invitation_id IS NULL) OR
  (source='INVITATION' AND source_request_id IS NULL AND source_enrollment_id IS NULL AND enrollment_version IS NULL AND source_invitation_id IS NOT NULL)),
 ADD CONSTRAINT fk_course_member_enrollment FOREIGN KEY(organization_id,account_id,organization_membership_id,source_enrollment_id) REFERENCES student_enrollment(organization_id,account_id,organization_membership_id,id),
 ADD CONSTRAINT fk_invited_group_member FOREIGN KEY(organization_id,group_id,account_id,organization_membership_id,source_invitation_id) REFERENCES group_invitation(organization_id,group_id,account_id,organization_membership_id,id);
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
 'GROUP_INVITATION_CREATED','GROUP_INVITATION_ACCEPTED','GROUP_INVITATION_REVOKED'));
