-- Baseline and category ceilings remain independently editable in the developer role manager.
INSERT INTO iam_context_member_role_binding(category_key,role_id,status,version)
 SELECT 'ORGANIZATION',UNHEX(MD5('professional-role:ORG_EMPLOYEE')),'ACTIVE',1
 WHERE NOT EXISTS(SELECT 1 FROM iam_context_member_role_binding WHERE category_key='ORGANIZATION');
-- Professional defaults do not inherit personal-group or developer control-plane actions.
DELETE ra FROM iam_role_authority ra JOIN iam_authority a ON a.id=ra.authority_id
 JOIN iam_role r ON r.id=ra.role_id
 WHERE r.role_key IN('PROFESSIONAL_CATEGORY','ORG_ADMIN') AND a.service_id='auth-service'
 AND a.id<>UNHEX(MD5(CONCAT('professional-authority:',a.authority_key)));

CREATE TABLE iam_professional_reconciliation (
 organization_id BINARY(16) NOT NULL,source_account_id BINARY(16) NOT NULL,target_account_id BINARY(16) NOT NULL,
 source_membership_id BINARY(16) NOT NULL,target_membership_id BINARY(16) NOT NULL,
 developer_account_id BINARY(16) NOT NULL,created_at DATETIME(6) NOT NULL,
 PRIMARY KEY(organization_id,source_account_id),
 UNIQUE KEY professional_reconciliation_target(organization_id,target_account_id),
 CONSTRAINT fk_professional_reconciliation_org FOREIGN KEY(organization_id) REFERENCES organization(id),
 CONSTRAINT fk_professional_reconciliation_source FOREIGN KEY(source_account_id) REFERENCES user_account(id),
 CONSTRAINT fk_professional_reconciliation_target FOREIGN KEY(target_account_id) REFERENCES user_account(id),
 CONSTRAINT chk_professional_reconciliation_distinct CHECK(source_account_id<>target_account_id)
);
UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL';
