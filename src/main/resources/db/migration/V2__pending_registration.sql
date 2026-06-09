CREATE TABLE pending_registration (
    id BINARY(16) NOT NULL PRIMARY KEY,
    registration_type VARCHAR(32) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    identifier VARCHAR(254) NOT NULL,
    identity_type VARCHAR(32) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    verified_at DATETIME(6) NULL,
    completed_at DATETIME(6) NULL,
    CONSTRAINT chk_registration_status CHECK (status IN
        ('PENDING_VERIFICATION', 'VERIFIED', 'COMPLETED', 'EXPIRED', 'CANCELLED')),
    CONSTRAINT chk_registration_type CHECK (registration_type = 'PERSONAL'),
    CONSTRAINT chk_identity_type CHECK (identity_type = 'EMAIL'),
    INDEX ix_registration_expiration (status, expires_at),
    INDEX ix_registration_identifier (identifier)
);

CREATE TABLE registration_verification (
    id BINARY(16) NOT NULL PRIMARY KEY,
    pending_registration_id BINARY(16) NOT NULL,
    verification_type VARCHAR(32) NOT NULL,
    destination VARCHAR(254) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    attempt_count INT NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    verified_at DATETIME(6) NULL,
    CONSTRAINT fk_verification_registration FOREIGN KEY (pending_registration_id)
        REFERENCES pending_registration (id),
    CONSTRAINT uq_verification_registration UNIQUE (pending_registration_id),
    CONSTRAINT chk_verification_status CHECK (status IN ('PENDING', 'VERIFIED', 'EXPIRED', 'FAILED', 'REVOKED')),
    CONSTRAINT chk_verification_type CHECK (verification_type = 'EMAIL_TOKEN'),
    CONSTRAINT chk_verification_attempts CHECK (attempt_count BETWEEN 0 AND 5),
    INDEX ix_verification_expiration (status, expires_at)
);
