-- Student admission, appointments and enforcement are independent of legacy organization rank.
CREATE TABLE iam_student_admin (
 organization_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL,
 account_id BINARY(16) NOT NULL, role_id BINARY(16) NOT NULL,
 status VARCHAR(16) NOT NULL, version BIGINT NOT NULL DEFAULT 1,
 PRIMARY KEY(organization_id,membership_id),
 CONSTRAINT fk_student_admin_member FOREIGN KEY(organization_id,membership_id,account_id) REFERENCES organization_membership(organization_id,id,account_id),
 CONSTRAINT fk_student_admin_role FOREIGN KEY(role_id) REFERENCES iam_role(id),
 CONSTRAINT chk_student_admin CHECK(status IN('ACTIVE','REVOKED') AND version>0)
);
CREATE TABLE iam_student_state (
 organization_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL,
 account_id BINARY(16) NOT NULL, status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
 version BIGINT NOT NULL DEFAULT 1,
 PRIMARY KEY(organization_id,membership_id), UNIQUE KEY uq_student_account(organization_id,account_id),
 CONSTRAINT fk_student_state_member FOREIGN KEY(organization_id,membership_id,account_id) REFERENCES organization_membership(organization_id,id,account_id),
 CONSTRAINT chk_student_state CHECK(status IN('ACTIVE','COLLABORATION_RESTRICTED','REMOVED_INTRUDER','REMOVED_TERMINATED') AND version>0)
);
INSERT INTO iam_student_state(organization_id,membership_id,account_id)
 SELECT a.organization_id,a.membership_id,a.student_account_id FROM student_admission a
 JOIN organization_membership m ON m.id=a.membership_id AND m.status='ACTIVE'
 WHERE a.status='APPROVED' AND a.student_account_id IS NOT NULL;
CREATE TABLE iam_semester_workspace (
 semester_id BINARY(16) NOT NULL PRIMARY KEY, organization_id BINARY(16) NOT NULL,
 workspace_id BINARY(16) NOT NULL, status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
 version BIGINT NOT NULL DEFAULT 1, requested_by BINARY(16) NOT NULL,
 CONSTRAINT fk_student_semester FOREIGN KEY(organization_id,semester_id) REFERENCES academic_semester(organization_id,id),
 UNIQUE KEY uq_semester_workspace(workspace_id),
 CONSTRAINT chk_semester_workspace CHECK(status IN('PENDING','READY') AND version>0)
);
CREATE TABLE iam_course_offering (
 group_id BINARY(16) NOT NULL PRIMARY KEY, organization_id BINARY(16) NOT NULL,
 UNIQUE KEY uq_student_course_scope(organization_id,group_id),
 semester_id BINARY(16) NOT NULL, status VARCHAR(16) NOT NULL DEFAULT 'DRAFT',
 version BIGINT NOT NULL DEFAULT 1, workspace_status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
 CONSTRAINT fk_student_course FOREIGN KEY(organization_id,group_id) REFERENCES iam_group(organization_id,id),
 CONSTRAINT fk_student_course_semester FOREIGN KEY(organization_id,semester_id) REFERENCES academic_semester(organization_id,id),
 CONSTRAINT chk_student_course CHECK(status IN('DRAFT','OFFERED','FINALIZED','RETIRED') AND workspace_status IN('PENDING','READY') AND version>0),
 INDEX ix_student_catalog(organization_id,status,group_id)
);
-- Legacy offerings remain closed until explicitly reconciled by the new catalog workflow.
INSERT INTO iam_course_offering(group_id,organization_id,semester_id)
 SELECT g.id,g.organization_id,r.semester_id FROM iam_group g JOIN group_rule r ON r.group_id=g.id
 JOIN organization o ON o.id=g.organization_id AND o.type='UNIVERSITY'
 WHERE g.type='COURSE' AND r.semester_id IS NOT NULL;
CREATE TABLE iam_student_course (
 organization_id BINARY(16) NOT NULL, group_id BINARY(16) NOT NULL,
 membership_id BINARY(16) NOT NULL, account_id BINARY(16) NOT NULL,
 id BINARY(16) NOT NULL, version BIGINT NOT NULL DEFAULT 1, joined_at DATETIME(6) NOT NULL,
 PRIMARY KEY(group_id,membership_id), UNIQUE KEY uq_student_course_id(id),
 CONSTRAINT fk_student_join_course FOREIGN KEY(organization_id,group_id) REFERENCES iam_course_offering(organization_id,group_id),
 CONSTRAINT fk_student_join_member FOREIGN KEY(organization_id,membership_id,account_id) REFERENCES organization_membership(organization_id,id,account_id),
 CONSTRAINT chk_student_join_version CHECK(version>0)
);
CREATE TABLE iam_study_group (
 id BINARY(16) NOT NULL PRIMARY KEY, organization_id BINARY(16) NOT NULL,
 course_id BINARY(16) NOT NULL, owner_account_id BINARY(16) NOT NULL,
 name VARCHAR(100) NOT NULL, request_id BINARY(16) NOT NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE', version BIGINT NOT NULL DEFAULT 1,
 notice_batch_id BINARY(16) NULL, purge_after DATETIME(6) NULL,deletion_requested_at DATETIME(6) NULL,
 deletion_notice_seconds BIGINT NOT NULL DEFAULT 604800,
 workspace_status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
 UNIQUE KEY uq_study_creation(owner_account_id,request_id),
 CONSTRAINT fk_study_course FOREIGN KEY(organization_id,course_id) REFERENCES iam_course_offering(organization_id,group_id),
 CONSTRAINT fk_study_owner FOREIGN KEY(owner_account_id) REFERENCES user_account(id),
 CONSTRAINT chk_study_status CHECK((status='ACTIVE' AND purge_after IS NULL AND notice_batch_id IS NULL)
 OR(status='PREPARING' AND purge_after IS NULL AND notice_batch_id IS NULL)
 OR(status='CLOSING' AND purge_after IS NOT NULL AND notice_batch_id IS NOT NULL)),
 CONSTRAINT chk_study_version CHECK(version>0 AND workspace_status IN('PENDING','READY') AND deletion_notice_seconds BETWEEN 2 AND 604800),
 CONSTRAINT chk_study_requested CHECK((status='ACTIVE' AND deletion_requested_at IS NULL) OR (status<>'ACTIVE' AND deletion_requested_at IS NOT NULL))
);
CREATE TABLE iam_study_member (
 group_id BINARY(16) NOT NULL, account_id BINARY(16) NOT NULL,
 id BINARY(16) NOT NULL, status VARCHAR(16) NOT NULL, version BIGINT NOT NULL DEFAULT 1,
 PRIMARY KEY(group_id,account_id), UNIQUE KEY uq_study_member_id(id),
 CONSTRAINT fk_study_member_group FOREIGN KEY(group_id) REFERENCES iam_study_group(id),
 CONSTRAINT fk_study_member_account FOREIGN KEY(account_id) REFERENCES user_account(id),
 CONSTRAINT chk_study_member CHECK(status IN('ACTIVE','REVOKED') AND version>0)
);
CREATE TABLE iam_study_invitation (
 id BINARY(16) NOT NULL PRIMARY KEY, group_id BINARY(16) NOT NULL,
 recipient_account_id BINARY(16) NOT NULL, request_id BINARY(16) NOT NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'PENDING', expires_at DATETIME(6) NOT NULL,
 version BIGINT NOT NULL DEFAULT 1,
 pending_account BINARY(16) GENERATED ALWAYS AS(IF(status='PENDING',recipient_account_id,NULL)) STORED,
 UNIQUE KEY uq_study_invite_request(group_id,request_id), UNIQUE KEY uq_study_pending(group_id,pending_account),
 CONSTRAINT fk_study_invite_group FOREIGN KEY(group_id) REFERENCES iam_study_group(id),
 CONSTRAINT fk_study_invite_account FOREIGN KEY(recipient_account_id) REFERENCES user_account(id),
 CONSTRAINT chk_study_invite CHECK(status IN('PENDING','ACCEPTED','DECLINED','REVOKED') AND version>0)
);
CREATE TABLE iam_student_report (
 id BINARY(16) NOT NULL PRIMARY KEY, organization_id BINARY(16) NOT NULL,
 course_id BINARY(16) NOT NULL, reporter_account_id BINARY(16) NOT NULL,
 target_account_id BINARY(16) NOT NULL, evidence_reference CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_id BINARY(16) NOT NULL, status VARCHAR(16) NOT NULL DEFAULT 'SUBMITTED',
 review_evidence_reference CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL, reviewed_by BINARY(16) NULL,
 version BIGINT NOT NULL DEFAULT 1,
 UNIQUE KEY uq_student_report_request(reporter_account_id,request_id),
 CONSTRAINT fk_student_report_course FOREIGN KEY(organization_id,course_id) REFERENCES iam_course_offering(organization_id,group_id),
 INDEX ix_student_report_evidence(evidence_reference),INDEX ix_student_report_review_evidence(review_evidence_reference),
 CONSTRAINT chk_student_report CHECK(status IN('SUBMITTED','REVIEWED','ESCALATED','CLOSED') AND version>0)
);
CREATE TABLE iam_student_report_evidence (
 id BINARY(16) NOT NULL PRIMARY KEY, organization_id BINARY(16) NOT NULL,
 course_id BINARY(16) NOT NULL, report_id BINARY(16) NULL,
 uploaded_by BINARY(16) NOT NULL, object_key VARCHAR(512) NOT NULL,
 content_type VARCHAR(64) NOT NULL, content_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 status VARCHAR(16) NOT NULL, created_at DATETIME(6) NOT NULL,
 CONSTRAINT fk_student_evidence_course FOREIGN KEY(organization_id,course_id) REFERENCES iam_course_offering(organization_id,group_id),
 CONSTRAINT fk_student_evidence_report FOREIGN KEY(report_id) REFERENCES iam_student_report(id),
 CONSTRAINT chk_student_evidence_status CHECK(status IN('PENDING','READY','EXPIRED')),
 INDEX ix_student_evidence_cleanup(created_at,status),INDEX ix_student_evidence_owner(uploaded_by,created_at)
);
-- Evidence references are private evidence-store identifiers, never raw evidence or arbitrary URLs.
CREATE TABLE iam_student_enforcement_proof (
 id BINARY(16) NOT NULL PRIMARY KEY, organization_id BINARY(16) NOT NULL,
 target_account_id BINARY(16) NOT NULL, report_id BINARY(16) NULL,
 proof_kind VARCHAR(32) NOT NULL, evidence_reference VARCHAR(512) NOT NULL,
 verified_by BINARY(16) NOT NULL, verified_at DATETIME(6) NOT NULL,
 CONSTRAINT fk_student_proof_report FOREIGN KEY(report_id) REFERENCES iam_student_report(id),
 CONSTRAINT chk_student_proof_kind CHECK(proof_kind IN('POLICY_VIOLATION','INTRUDER','STUDENTSHIP_TERMINATION'))
);
CREATE TABLE iam_student_audit (
 id BINARY(16) NOT NULL PRIMARY KEY, organization_id BINARY(16) NOT NULL,
 actor_account_id BINARY(16) NOT NULL, session_id BINARY(16) NULL,
 aggregate_id BINARY(16) NOT NULL, event_type VARCHAR(64) NOT NULL,
 authorization_version BIGINT NOT NULL, occurred_at DATETIME(6) NOT NULL
);
CREATE TABLE iam_student_decision (
 organization_id BINARY(16) NOT NULL, request_id BINARY(16) NOT NULL,
 target_account_id BINARY(16) NOT NULL, proof_id BINARY(16) NOT NULL,
 action_key VARCHAR(32) NOT NULL, expected_version BIGINT NOT NULL,
 result_status VARCHAR(32) NOT NULL, result_version BIGINT NOT NULL, actor_account_id BINARY(16) NOT NULL,
 PRIMARY KEY(organization_id,request_id),
 CONSTRAINT fk_student_decision_proof FOREIGN KEY(proof_id) REFERENCES iam_student_enforcement_proof(id),
 CONSTRAINT chk_student_decision_version CHECK(expected_version>0 AND result_version>expected_version)
);
CREATE TABLE iam_student_notice (
 id BINARY(16) NOT NULL PRIMARY KEY, organization_id BINARY(16) NOT NULL,
 recipient_account_id BINARY(16) NOT NULL, aggregate_id BINARY(16) NOT NULL,
 event_type VARCHAR(64) NOT NULL, authorization_version BIGINT NOT NULL, occurred_at DATETIME(6) NOT NULL,
 INDEX ix_student_notice(recipient_account_id,id)
);
CREATE TABLE iam_student_role_binding (
 responsibility VARCHAR(16) NOT NULL PRIMARY KEY, role_id BINARY(16) NOT NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE', version BIGINT NOT NULL DEFAULT 1,
 CONSTRAINT fk_student_binding_role FOREIGN KEY(role_id) REFERENCES iam_role(id),
 CONSTRAINT chk_student_binding CHECK(responsibility IN('STUDENT','STUDENT_ADMIN','STUDY_OWNER','STUDY_MEMBER') AND status IN('ACTIVE','DISABLED') AND version>0)
);
INSERT INTO iam_role(id,role_key,status,version,created_at,updated_at)
 SELECT UNHEX(MD5(CONCAT('student-role:',k))),k,'ACTIVE',1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)
 FROM JSON_TABLE('["STUDENT_CATEGORY","STUDENT","STUDENT_ADMIN","STUDY_GROUP_OWNER","STUDY_GROUP_MEMBER"]','$[*]' COLUMNS(k VARCHAR(128) PATH '$')) r;
INSERT INTO iam_student_role_binding(responsibility,role_id) VALUES
 ('STUDENT',UNHEX(MD5('student-role:STUDENT'))),('STUDENT_ADMIN',UNHEX(MD5('student-role:STUDENT_ADMIN'))),
 ('STUDY_OWNER',UNHEX(MD5('student-role:STUDY_GROUP_OWNER'))),('STUDY_MEMBER',UNHEX(MD5('student-role:STUDY_GROUP_MEMBER')));
INSERT INTO iam_stakeholder_role_binding
 SELECT 'STUDENT',UNHEX(MD5('student-role:STUDENT_CATEGORY')),'ACTIVE',1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)
 WHERE NOT EXISTS(SELECT 1 FROM iam_stakeholder_role_binding WHERE category_key='STUDENT');
INSERT INTO iam_authority(id,service_id,authority_key,status,version,created_at,updated_at)
 SELECT UNHEX(MD5(CONCAT('student-authority:',k))),'auth-service',k,'ACTIVE',1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)
 FROM JSON_TABLE('["student.admission.review","course.catalog.read","course.catalog.create","course.catalog.update","course.catalog.remove","semester.create","course.join","student.report.submit","student.report.review","student.report.evidence.submit","study.group.create"]','$[*]' COLUMNS(k VARCHAR(128) PATH '$')) a;
INSERT INTO iam_operation(id,service_id,operation_key,status,version,created_at,updated_at)
 SELECT UNHEX(MD5(CONCAT('student-operation:',authority_key))),service_id,authority_key,'ACTIVE',1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)
 FROM iam_authority WHERE id=UNHEX(MD5(CONCAT('student-authority:',authority_key)));
INSERT INTO iam_operation_policy(id,operation_id,service_id,match_mode,requires_scoped_authorities,status,version,created_at,updated_at)
 SELECT UNHEX(MD5(CONCAT('student-policy:',operation_key))),id,service_id,'ALL_OF',TRUE,'ACTIVE',1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)
 FROM iam_operation WHERE id=UNHEX(MD5(CONCAT('student-operation:',operation_key)));
INSERT INTO iam_policy_authority(policy_id,service_id,authority_id,authority_slot)
 SELECT p.id,p.service_id,a.id,1 FROM iam_operation_policy p JOIN iam_operation o ON o.id=p.operation_id
 JOIN iam_authority a ON a.service_id=o.service_id AND a.authority_key=o.operation_key
 WHERE p.id=UNHEX(MD5(CONCAT('student-policy:',o.operation_key)));
INSERT INTO iam_role_authority(role_id,authority_id)
 SELECT UNHEX(MD5('student-role:STUDENT_ADMIN')),id FROM iam_authority WHERE service_id='auth-service'
 AND authority_key IN('student.admission.review','course.catalog.read','course.catalog.create','course.catalog.update','course.catalog.remove','semester.create','student.report.review','student.report.evidence.submit');
INSERT INTO iam_role_authority(role_id,authority_id)
 SELECT UNHEX(MD5('student-role:STUDENT')),id FROM iam_authority WHERE
 (service_id='document-service' AND (authority_key LIKE 'file.%' OR authority_key LIKE 'folder.%' OR authority_key IN('workspace.read','quota.read','deletion.read','content.access.update')))
 OR (service_id='auth-service' AND authority_key IN('course.catalog.read','course.join','student.report.submit','study.group.create','group.read','group.invitation.accept','group.invitation.decline','group.leave'));
INSERT INTO iam_role_authority(role_id,authority_id)
 SELECT UNHEX(MD5('student-role:STUDY_GROUP_OWNER')),id FROM iam_authority WHERE service_id='auth-service'
 AND authority_key IN('group.read','group.invitation.issue','group.invitation.revoke','group.delete.schedule','group.delete.cancel');
INSERT INTO iam_role_authority(role_id,authority_id)
 SELECT UNHEX(MD5('student-role:STUDY_GROUP_MEMBER')),id FROM iam_authority WHERE service_id='auth-service' AND authority_key IN('group.read','group.leave');
INSERT INTO iam_role_authority(role_id,authority_id)
 SELECT DISTINCT UNHEX(MD5('student-role:STUDENT_CATEGORY')),ra.authority_id FROM iam_role_authority ra
 JOIN iam_student_role_binding b ON b.role_id=ra.role_id;
-- Retain legacy staff identities as reconciliation candidates; appointment remains developer-only.
CREATE TABLE iam_student_staff_reconciliation (
 organization_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'PENDING', target_account_id BINARY(16) NULL,target_membership_id BINARY(16) NULL,
 PRIMARY KEY(organization_id,membership_id),
 CONSTRAINT chk_student_staff_reconciliation CHECK(status IN('PENDING','RECONCILED'))
);
INSERT INTO iam_student_staff_reconciliation(organization_id,membership_id)
 SELECT DISTINCT m.organization_id,m.id FROM organization_membership m JOIN organization o ON o.id=m.organization_id
 LEFT JOIN institute_curator c ON c.membership_id=m.id AND c.organization_id=m.organization_id
 WHERE o.type='UNIVERSITY' AND m.status='ACTIVE' AND (m.role IN('OWNER','ADMIN') OR c.membership_id IS NOT NULL);
UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL';
INSERT IGNORE INTO iam_role_authority(role_id,authority_id)
 SELECT UNHEX(MD5('student-role:STUDENT')),id FROM iam_authority WHERE service_id='document-service' AND authority_key='workspace.create';
INSERT IGNORE INTO iam_role_authority(role_id,authority_id)
 SELECT UNHEX(MD5('student-role:STUDENT_CATEGORY')),id FROM iam_authority WHERE service_id='document-service' AND authority_key='workspace.create';
