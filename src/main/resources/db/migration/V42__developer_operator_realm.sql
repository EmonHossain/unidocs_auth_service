-- A developer operator is a separate principal and never owns a product account.
CREATE TABLE iam_developer_operator (
 id BINARY(16) NOT NULL PRIMARY KEY,
 bootstrap_key VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 username VARCHAR(128) NOT NULL,
 password_hash VARCHAR(255) NOT NULL,
 email VARCHAR(254) NULL,
 email_verified BOOLEAN NOT NULL DEFAULT FALSE,
 status VARCHAR(16) NOT NULL,
 credential_version BIGINT NOT NULL DEFAULT 1,
 activation_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 failed_attempts INT NOT NULL DEFAULT 0,
 lock_window_at DATETIME(6) NULL,
 created_at DATETIME(6) NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 UNIQUE KEY uq_developer_bootstrap_key(bootstrap_key),
 UNIQUE KEY uq_developer_username(username),
 CONSTRAINT chk_developer_operator_status CHECK(status IN ('SETUP','ACTIVE','DISABLED')),
 CONSTRAINT chk_developer_operator_version CHECK(credential_version>0),
 CONSTRAINT chk_developer_operator_attempts CHECK(failed_attempts BETWEEN 0 AND 5)
);
CREATE TABLE iam_developer_session (
 id BINARY(16) NOT NULL PRIMARY KEY,
 operator_id BINARY(16) NOT NULL,
 credential_version BIGINT NOT NULL,
 status VARCHAR(16) NOT NULL,
 authenticated_at DATETIME(6) NOT NULL,
 expires_at DATETIME(6) NOT NULL,
 refresh_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 refresh_expires_at DATETIME(6) NOT NULL,
 rotation BIGINT NOT NULL DEFAULT 0,
 created_at DATETIME(6) NOT NULL,
 revoked_at DATETIME(6) NULL,
 CONSTRAINT fk_developer_session_operator FOREIGN KEY(operator_id) REFERENCES iam_developer_operator(id),
 CONSTRAINT chk_developer_session_status CHECK(status IN ('ACTIVE','REVOKED')),
 INDEX ix_developer_session_operator(operator_id,status,expires_at)
);
CREATE TABLE iam_developer_operator_factor (
 secret_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 operator_id BINARY(16) NOT NULL,
 expires_at DATETIME(6) NOT NULL,
 consumed_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
 consumed_at DATETIME(6) NULL,
 CONSTRAINT fk_developer_operator_factor FOREIGN KEY(operator_id) REFERENCES iam_developer_operator(id),
 INDEX ix_developer_operator_factor(operator_id,expires_at)
);
CREATE TABLE iam_developer_setup_proof (
 operator_id BINARY(16) NOT NULL PRIMARY KEY,
 pending_username VARCHAR(128) NOT NULL,
 pending_password_hash VARCHAR(255) NOT NULL,
 pending_email VARCHAR(254) NOT NULL,
 code_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 expires_at DATETIME(6) NOT NULL,
 failed_attempts INT NOT NULL DEFAULT 0,
 delivery_state VARCHAR(16) NOT NULL,
 created_at DATETIME(6) NOT NULL,
 CONSTRAINT fk_developer_setup_operator FOREIGN KEY(operator_id) REFERENCES iam_developer_operator(id),
 CONSTRAINT chk_developer_setup_attempts CHECK(failed_attempts BETWEEN 0 AND 5),
 CONSTRAINT chk_developer_setup_delivery CHECK(delivery_state IN ('PENDING','SENT','FAILED'))
);
CREATE TABLE iam_developer_operator_audit (
 id BINARY(16) NOT NULL PRIMARY KEY,
 operator_id BINARY(16) NOT NULL,
 session_id BINARY(16) NULL,
 action_key VARCHAR(64) NOT NULL,
 aggregate_id BINARY(16) NULL,
 aggregate_version BIGINT NULL,
 reason VARCHAR(512) NULL,
 occurred_at DATETIME(6) NOT NULL,
 CONSTRAINT fk_developer_operator_audit_actor FOREIGN KEY(operator_id) REFERENCES iam_developer_operator(id),
 INDEX ix_developer_operator_audit(operator_id,occurred_at,id)
);
CREATE TABLE iam_developer_operator_request (
 operator_id BINARY(16) NOT NULL,
 idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 result_id BINARY(16) NOT NULL,
 result_version BIGINT NOT NULL,
 created_at DATETIME(6) NOT NULL,
 PRIMARY KEY(operator_id,idempotency_key),
 CONSTRAINT fk_developer_operator_request_actor FOREIGN KEY(operator_id) REFERENCES iam_developer_operator(id)
);
