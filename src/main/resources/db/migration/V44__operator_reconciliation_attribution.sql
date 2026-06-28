ALTER TABLE organization_membership
 ADD COLUMN revoked_by_operator_id BINARY(16) NULL,
 ADD CONSTRAINT fk_org_member_revoked_operator FOREIGN KEY(revoked_by_operator_id) REFERENCES iam_developer_operator(id),
 DROP CHECK chk_org_member_revocation,
 ADD CONSTRAINT chk_org_member_revocation CHECK (
  (status='ACTIVE' AND revoked_at IS NULL AND revoked_by IS NULL AND revoked_by_operator_id IS NULL)
  OR (status IN('REVOKED','PURGED') AND revoked_at IS NOT NULL
      AND ((revoked_by IS NOT NULL AND revoked_by_operator_id IS NULL)
        OR (revoked_by IS NULL AND revoked_by_operator_id IS NOT NULL)))
 );

ALTER TABLE group_membership
 ADD COLUMN assigned_by_operator_id BINARY(16) NULL,
 ADD COLUMN revoked_by_operator_id BINARY(16) NULL,
 ADD CONSTRAINT fk_group_assigned_operator FOREIGN KEY(assigned_by_operator_id) REFERENCES iam_developer_operator(id),
 ADD CONSTRAINT fk_group_revoked_operator FOREIGN KEY(revoked_by_operator_id) REFERENCES iam_developer_operator(id),
 MODIFY assigned_by_account_id BINARY(16) NULL,
 DROP CHECK chk_group_member_revocation,
 ADD CONSTRAINT chk_group_member_revocation CHECK (
  (status='ACTIVE' AND revoked_at IS NULL AND revoked_by_account_id IS NULL AND revoked_by_operator_id IS NULL)
  OR (status='REVOKED' AND revoked_at IS NOT NULL
      AND ((revoked_by_account_id IS NOT NULL AND revoked_by_operator_id IS NULL)
        OR (revoked_by_account_id IS NULL AND revoked_by_operator_id IS NOT NULL)))
 ),
 ADD CONSTRAINT chk_group_assignment_actor CHECK (
  (assigned_by_account_id IS NOT NULL AND assigned_by_operator_id IS NULL)
  OR (assigned_by_account_id IS NULL AND assigned_by_operator_id IS NOT NULL)
 ),
 ADD UNIQUE KEY uq_group_operator_assignment_request(organization_id,assigned_by_operator_id,assignment_request_id);

ALTER TABLE iam_professional_reconciliation
 MODIFY developer_account_id BINARY(16) NULL,
 ADD COLUMN developer_operator_id BINARY(16) NULL,
 ADD CONSTRAINT fk_professional_reconciliation_operator FOREIGN KEY(developer_operator_id) REFERENCES iam_developer_operator(id),
 ADD CONSTRAINT chk_professional_reconciliation_actor CHECK (
  (developer_account_id IS NOT NULL AND developer_operator_id IS NULL)
  OR (developer_account_id IS NULL AND developer_operator_id IS NOT NULL)
 );
