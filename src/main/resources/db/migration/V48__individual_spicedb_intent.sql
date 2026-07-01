-- Immutable, source-qualified personal capability snapshots. Current SQL admission
-- is still required; these rows and graph tokens are never permission leases.
CREATE TABLE iam_individual_graph_intent (
    snapshot_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
    account_id BINARY(16) NOT NULL,
    group_id BINARY(16) NULL,
    created_at TIMESTAMP(6) NOT NULL,
    applied_at TIMESTAMP(6) NULL,
    zed_token TEXT NULL,
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX ix_individual_graph_pending (applied_at, next_attempt_at, created_at)
);

CREATE TABLE iam_individual_graph_authority (
    snapshot_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    authority_id BINARY(16) NOT NULL,
    category_granted BOOLEAN NOT NULL,
    local_granted BOOLEAN NOT NULL,
    PRIMARY KEY (snapshot_id, authority_id),
    CONSTRAINT fk_individual_graph_intent FOREIGN KEY (snapshot_id)
        REFERENCES iam_individual_graph_intent(snapshot_id)
);
