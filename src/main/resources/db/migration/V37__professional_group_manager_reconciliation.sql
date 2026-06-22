-- Convert current professional group managers once; legacy flags never grant professional authority at runtime.
ALTER TABLE iam_professional_restriction ADD INDEX ix_professional_restriction_current(organization_id,operation_id,status,account_id,valid_from,valid_until);
INSERT INTO iam_professional_assignment(id,organization_id,membership_id,account_id,group_id,role_id,status,valid_from,valid_until,version)
 SELECT UNHEX(MD5(CONCAT('professional-manager:',HEX(gm.id)))),gm.organization_id,gm.organization_membership_id,gm.account_id,gm.group_id,
 UNHEX(MD5(IF(g.type='DEPARTMENT','professional-role:DEPARTMENT_ADMIN','professional-role:TEAM_ADMIN'))),
 'ACTIVE',gm.valid_from,gm.valid_until,1
 FROM group_membership gm JOIN iam_group g ON g.id=gm.group_id AND g.organization_id=gm.organization_id AND g.status='ACTIVE'
 JOIN organization o ON o.id=gm.organization_id AND o.type IN('COMPANY','CUSTOM') AND o.status='ACTIVE'
 JOIN organization_membership m ON m.id=gm.organization_membership_id AND m.organization_id=gm.organization_id AND m.account_id=gm.account_id AND m.status='ACTIVE'
 JOIN user_account a ON a.id=gm.account_id AND a.status='ACTIVE'
 WHERE gm.status='ACTIVE' AND gm.can_manage_group=TRUE
 AND (gm.valid_until IS NULL OR gm.valid_until>UTC_TIMESTAMP(6));
-- Close professional admission configuration; membership is assigned through scoped admin use cases.
UPDATE group_rule r JOIN organization o ON o.id=r.organization_id AND o.type IN('COMPANY','CUSTOM')
 SET r.join_rule='INVITATION_ONLY',r.version=r.version+1 WHERE r.join_rule<>'INVITATION_ONLY';
UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL';
