CREATE TABLE iam_developer_recovery_code (
 secret_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 operator_id BINARY(16) NOT NULL,
 consumed_at DATETIME(6) NULL,
 created_at DATETIME(6) NOT NULL,
 CONSTRAINT fk_developer_recovery_code_operator FOREIGN KEY(operator_id) REFERENCES iam_developer_operator(id),
 INDEX ix_developer_recovery_code_operator(operator_id,consumed_at)
);

CREATE TABLE iam_developer_recovery_proof (
 operator_id BINARY(16) NOT NULL PRIMARY KEY,
 token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 credential_version BIGINT NOT NULL,
 expires_at DATETIME(6) NOT NULL,
 failed_attempts INT NOT NULL DEFAULT 0,
 delivery_state VARCHAR(16) NOT NULL,
 created_at DATETIME(6) NOT NULL,
 consumed_at DATETIME(6) NULL,
 CONSTRAINT fk_developer_recovery_proof_operator FOREIGN KEY(operator_id) REFERENCES iam_developer_operator(id),
 CONSTRAINT chk_developer_recovery_attempts CHECK(failed_attempts BETWEEN 0 AND 5),
 CONSTRAINT chk_developer_recovery_delivery CHECK(delivery_state IN ('PENDING','SENT','FAILED'))
);

CREATE TABLE iam_developer_security_notice (
 id BINARY(16) NOT NULL PRIMARY KEY,
 operator_id BINARY(16) NOT NULL,
 action_key VARCHAR(64) NOT NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
 attempts INT NOT NULL DEFAULT 0,
 available_at DATETIME(6) NOT NULL,
 claim_token BINARY(16) NULL,
 lease_until DATETIME(6) NULL,
 created_at DATETIME(6) NOT NULL,
 CONSTRAINT fk_developer_security_notice_operator FOREIGN KEY(operator_id) REFERENCES iam_developer_operator(id),
 CONSTRAINT chk_developer_security_notice_status CHECK(status IN ('PENDING','SENT')),
 INDEX ix_developer_security_notice_pending(status,available_at,id)
);
