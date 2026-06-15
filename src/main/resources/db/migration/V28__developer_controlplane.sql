-- No bootstrap identity: eligibility is provisioned only through the audited operator procedure.
CREATE TABLE iam_developer_eligibility (
 account_id BINARY(16) NOT NULL PRIMARY KEY,
 status VARCHAR(16) NOT NULL,
 version BIGINT NOT NULL,
 provisioned_by VARCHAR(128) NOT NULL,
 reason VARCHAR(512) NOT NULL,
 failed_attempts INT NOT NULL DEFAULT 0,
 proof_window_at TIMESTAMP(6) NULL,
 updated_at TIMESTAMP(6) NOT NULL,
 CONSTRAINT fk_developer_account FOREIGN KEY(account_id) REFERENCES user_account(id),
 CONSTRAINT chk_developer_status CHECK(status IN ('ACTIVE','REVOKED')),
 CONSTRAINT chk_developer_version CHECK(version>=1),
 CONSTRAINT chk_developer_attempts CHECK(failed_attempts BETWEEN 0 AND 5)
);
CREATE TABLE iam_controlplane_audit (
 id BINARY(16) NOT NULL PRIMARY KEY,
 account_id BINARY(16) NOT NULL,
 session_id BINARY(16) NULL,
 action_key VARCHAR(64) NOT NULL,
 aggregate_id BINARY(16) NOT NULL,
 aggregate_version BIGINT NOT NULL,
 operator_reference VARCHAR(128) NULL,
 reason VARCHAR(512) NULL,
 occurred_at TIMESTAMP(6) NOT NULL,
 INDEX ix_controlplane_audit_account(account_id,occurred_at,id)
);
CREATE TABLE iam_controlplane_request (
 account_id BINARY(16) NOT NULL,
 idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 result_id BINARY(16) NOT NULL,
 result_version BIGINT NOT NULL,
 created_at TIMESTAMP(6) NOT NULL,
 PRIMARY KEY(account_id,idempotency_key)
);
CREATE TABLE iam_developer_factor (
 secret_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 account_id BINARY(16) NOT NULL,
 expires_at TIMESTAMP(6) NOT NULL,
 consumed_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
 consumed_at TIMESTAMP(6) NULL,
 CONSTRAINT fk_developer_factor FOREIGN KEY(account_id) REFERENCES iam_developer_eligibility(account_id),
 INDEX ix_developer_factor_account(account_id,expires_at)
);
