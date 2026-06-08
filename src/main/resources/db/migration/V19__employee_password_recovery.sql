CREATE TABLE employee_password_recovery (
 id BINARY(16) NOT NULL PRIMARY KEY,
 account_id BINARY(16) NOT NULL,
 organization_id BINARY(16) NOT NULL,
 status VARCHAR(32) NOT NULL,
 pin_hash VARCHAR(255) NULL,
 credential_version BIGINT NOT NULL DEFAULT 0,
 attempts INT NOT NULL DEFAULT 0,
 requested_at DATETIME(6) NOT NULL,
 issued_at DATETIME(6) NULL,
 completed_at DATETIME(6) NULL,
 CONSTRAINT uq_employee_recovery_account UNIQUE(account_id),
 CONSTRAINT fk_employee_recovery_account FOREIGN KEY(account_id) REFERENCES user_account(id),
 CONSTRAINT fk_employee_recovery_org FOREIGN KEY(organization_id) REFERENCES organization(id),
 CONSTRAINT chk_employee_recovery_status CHECK(status IN('REQUESTED','PIN_ISSUED','LOCKED','COMPLETED')),
 CONSTRAINT chk_employee_recovery_attempts CHECK(attempts BETWEEN 0 AND 5),
 INDEX ix_employee_recovery_org(organization_id,status,id)
);
