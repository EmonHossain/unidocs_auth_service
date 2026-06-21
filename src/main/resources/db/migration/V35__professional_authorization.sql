-- Professional responsibilities are data, separate from legacy navigation roles.
CREATE TABLE iam_professional_responsibility (
 role_id BINARY(16) NOT NULL PRIMARY KEY,
 scope_kind VARCHAR(16) NOT NULL,
 CONSTRAINT fk_professional_role FOREIGN KEY(role_id) REFERENCES iam_role(id),
 CONSTRAINT chk_professional_scope CHECK(scope_kind IN('ORGANIZATION','DEPARTMENT','TEAM'))
);
CREATE TABLE iam_professional_assignment (
 id BINARY(16) NOT NULL PRIMARY KEY,
 organization_id BINARY(16) NOT NULL,
 membership_id BINARY(16) NOT NULL,
 account_id BINARY(16) NOT NULL,
 group_id BINARY(16) NULL,
 role_id BINARY(16) NOT NULL,
 status VARCHAR(16) NOT NULL,
 valid_from DATETIME(6) NOT NULL,
 valid_until DATETIME(6) NULL,
 version BIGINT NOT NULL DEFAULT 1,
 scope_key BINARY(16) GENERATED ALWAYS AS(COALESCE(group_id,organization_id)) STORED,
 UNIQUE KEY uq_professional_assignment(organization_id,membership_id,scope_key,role_id),
 CONSTRAINT fk_professional_assignment_member FOREIGN KEY(organization_id,membership_id,account_id) REFERENCES organization_membership(organization_id,id,account_id),
 CONSTRAINT fk_professional_assignment_group FOREIGN KEY(organization_id,group_id) REFERENCES iam_group(organization_id,id),
 CONSTRAINT fk_professional_assignment_role FOREIGN KEY(role_id) REFERENCES iam_professional_responsibility(role_id),
 CONSTRAINT chk_professional_assignment CHECK(status IN('ACTIVE','REVOKED') AND version>0 AND (valid_until IS NULL OR valid_until>valid_from)),
 INDEX ix_professional_actor(organization_id,account_id,status)
);
CREATE TABLE iam_professional_restriction (
 id BINARY(16) NOT NULL PRIMARY KEY,
 organization_id BINARY(16) NOT NULL,
 group_id BINARY(16) NULL,
 account_id BINARY(16) NULL,
 operation_id BINARY(16) NOT NULL,
 status VARCHAR(16) NOT NULL,
 valid_from DATETIME(6) NOT NULL,
 valid_until DATETIME(6) NULL,
 version BIGINT NOT NULL DEFAULT 1,
 scope_key BINARY(16) GENERATED ALWAYS AS(COALESCE(group_id,organization_id)) STORED,
 target_key BINARY(16) GENERATED ALWAYS AS(COALESCE(account_id,UNHEX('00000000000000000000000000000000'))) STORED,
 UNIQUE KEY uq_professional_restriction(organization_id,scope_key,target_key,operation_id),
 CONSTRAINT fk_professional_restriction_org FOREIGN KEY(organization_id) REFERENCES organization(id),
 CONSTRAINT fk_professional_restriction_group FOREIGN KEY(organization_id,group_id) REFERENCES iam_group(organization_id,id),
 CONSTRAINT fk_professional_restriction_account FOREIGN KEY(account_id) REFERENCES user_account(id),
 CONSTRAINT fk_professional_restriction_operation FOREIGN KEY(operation_id) REFERENCES iam_operation(id),
 CONSTRAINT chk_professional_restriction CHECK(status IN('ACTIVE','REVOKED') AND version>0 AND (valid_until IS NULL OR valid_until>valid_from))
);
CREATE TABLE iam_professional_audit (
 id BINARY(16) NOT NULL PRIMARY KEY,organization_id BINARY(16) NOT NULL,
 actor_account_id BINARY(16) NOT NULL,session_id BINARY(16) NOT NULL,
 target_account_id BINARY(16) NULL,event_type VARCHAR(64) NOT NULL,
 authorization_version BIGINT NOT NULL,created_at DATETIME(6) NOT NULL
);
CREATE TABLE iam_professional_notice (
 id BINARY(16) NOT NULL PRIMARY KEY,
 organization_id BINARY(16) NOT NULL,
 recipient_account_id BINARY(16) NOT NULL,
 authorization_version BIGINT NOT NULL,
 event_type VARCHAR(64) NOT NULL,
 created_at DATETIME(6) NOT NULL,
 INDEX ix_professional_notice(recipient_account_id,id),
 CONSTRAINT fk_professional_notice_org FOREIGN KEY(organization_id) REFERENCES organization(id)
);

INSERT INTO iam_role(id,role_key,status,version,created_at,updated_at)
 SELECT UNHEX(MD5(CONCAT('professional-role:',k))),k,'ACTIVE',1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)
 FROM JSON_TABLE('["PROFESSIONAL_CATEGORY","ORG_EMPLOYEE","ORG_ADMIN","DEPARTMENT_ADMIN","TEAM_ADMIN"]','$[*]' COLUMNS(k VARCHAR(128) PATH '$')) roles;
INSERT INTO iam_stakeholder_role_binding
 SELECT 'ORGANIZATION',UNHEX(MD5('professional-role:PROFESSIONAL_CATEGORY')),'ACTIVE',1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)
 WHERE NOT EXISTS(SELECT 1 FROM iam_stakeholder_role_binding WHERE category_key='ORGANIZATION');
INSERT INTO iam_professional_responsibility VALUES
 (UNHEX(MD5('professional-role:ORG_ADMIN')),'ORGANIZATION'),
 (UNHEX(MD5('professional-role:DEPARTMENT_ADMIN')),'DEPARTMENT'),
 (UNHEX(MD5('professional-role:TEAM_ADMIN')),'TEAM');

INSERT INTO iam_authority(id,service_id,authority_key,status,version,created_at,updated_at)
 SELECT UNHEX(MD5(CONCAT('professional-authority:',k))),IF(k LIKE 'publication.%' OR k='organization.quota.read' OR k='organization.deletion.policy.update','document-service','auth-service'),k,'ACTIVE',1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)
 FROM JSON_TABLE('["organization.employee.create","organization.employee.remove","organization.employee.reset","organization.department.assign","organization.group.assign","organization.group.unassign","organization.group.create","organization.responsibility.assign","organization.access.update","department.access.update","team.access.update","organization.collaboration.invite","publication.submit","publication.approve","publication.reject","publication.read","publication.edit.own","publication.delete.schedule","organization.quota.read","organization.deletion.policy.update"]','$[*]' COLUMNS(k VARCHAR(128) PATH '$')) keys_to_seed;
INSERT INTO iam_operation(id,service_id,operation_key,status,version,created_at,updated_at)
 SELECT UNHEX(MD5(CONCAT('professional-operation:',authority_key))),service_id,authority_key,'ACTIVE',1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)
 FROM iam_authority WHERE id=UNHEX(MD5(CONCAT('professional-authority:',authority_key)));
INSERT INTO iam_operation_policy(id,operation_id,service_id,match_mode,requires_scoped_authorities,status,version,created_at,updated_at)
 SELECT UNHEX(MD5(CONCAT('professional-policy:',operation_key))),id,service_id,'ALL_OF',TRUE,'ACTIVE',1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)
 FROM iam_operation WHERE id=UNHEX(MD5(CONCAT('professional-operation:',operation_key)));
INSERT INTO iam_policy_authority(policy_id,service_id,authority_id,authority_slot)
 SELECT p.id,p.service_id,a.id,1 FROM iam_operation_policy p JOIN iam_operation o ON o.id=p.operation_id
 JOIN iam_authority a ON a.service_id=o.service_id AND a.authority_key=o.operation_key
 WHERE p.id=UNHEX(MD5(CONCAT('professional-policy:',o.operation_key)));
-- The category ceiling permits the inventory; local responsibility and privacy are separate.
INSERT INTO iam_role_authority(role_id,authority_id)
 SELECT UNHEX(MD5('professional-role:PROFESSIONAL_CATEGORY')),id FROM iam_authority WHERE status='ACTIVE';
INSERT INTO iam_role_authority(role_id,authority_id)
 SELECT UNHEX(MD5('professional-role:ORG_EMPLOYEE')),id FROM iam_authority
 WHERE service_id='document-service' AND status='ACTIVE' AND authority_key NOT IN('publication.approve','publication.reject','publication.delete.schedule','organization.quota.read','organization.deletion.policy.update','workspace.create')
 AND authority_key NOT LIKE 'group.%';
INSERT INTO iam_role_authority(role_id,authority_id)
 SELECT UNHEX(MD5('professional-role:ORG_ADMIN')),id FROM iam_authority WHERE status='ACTIVE';
INSERT INTO iam_role_authority(role_id,authority_id)
 SELECT UNHEX(MD5(CONCAT('professional-role:',r.k))),a.id FROM JSON_TABLE('["DEPARTMENT_ADMIN","TEAM_ADMIN"]','$[*]' COLUMNS(k VARCHAR(128) PATH '$')) r
 CROSS JOIN iam_authority a WHERE a.status='ACTIVE' AND
 (a.service_id='document-service' AND a.authority_key NOT LIKE 'publication.%' AND a.authority_key NOT LIKE 'organization.%' AND a.authority_key<>'workspace.create'
 OR a.authority_key IN('team.access.update','organization.collaboration.invite')
 OR r.k='DEPARTMENT_ADMIN' AND a.authority_key IN('organization.group.assign','organization.group.unassign','department.access.update'));
-- Reconcile current legacy organization administrators once. No runtime role-name fallback.
INSERT INTO iam_professional_assignment(id,organization_id,membership_id,account_id,group_id,role_id,status,valid_from,version)
 SELECT UNHEX(MD5(CONCAT('professional-admin:',HEX(m.id)))),m.organization_id,m.id,m.account_id,NULL,UNHEX(MD5('professional-role:ORG_ADMIN')),'ACTIVE',UTC_TIMESTAMP(6),1
 FROM organization_membership m JOIN organization o ON o.id=m.organization_id
 WHERE o.type<>'UNIVERSITY' AND m.status='ACTIVE' AND m.role IN('OWNER','ADMIN');
UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL';
