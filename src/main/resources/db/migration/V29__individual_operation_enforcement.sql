CREATE TABLE iam_policy_revision (
    id VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    revision BIGINT NOT NULL,
    CONSTRAINT chk_policy_revision CHECK (revision >= 1)
);
INSERT INTO iam_policy_revision VALUES ('GLOBAL', 1);

CREATE TABLE iam_group_relationship_role_binding (
    relationship_key VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    role_id BINARY(16) NOT NULL,
    status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    version BIGINT NOT NULL,
    CONSTRAINT fk_group_relationship_role FOREIGN KEY(role_id) REFERENCES iam_role(id),
    CONSTRAINT chk_group_relationship_key CHECK(relationship_key IN ('OWNER','MEMBER')),
    CONSTRAINT chk_group_relationship_status CHECK(status IN ('ACTIVE','DISABLED')),
    CONSTRAINT chk_group_relationship_version CHECK(version >= 1)
);

-- Local baseline capabilities are distinct from the category ceiling; linked accounts never union them.
CREATE TABLE iam_context_member_role_binding (
    category_key VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    role_id BINARY(16) NOT NULL,
    status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    version BIGINT NOT NULL,
    CONSTRAINT fk_context_member_role FOREIGN KEY (role_id) REFERENCES iam_role(id),
    CONSTRAINT chk_context_member_status CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT chk_context_member_version CHECK (version >= 1)
);

CREATE TABLE iam_operation_restriction (
    id BINARY(16) NOT NULL PRIMARY KEY,
    operation_id BINARY(16) NOT NULL,
    category_key VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    account_id BINARY(16) NULL,
    status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    version BIGINT NOT NULL,
    valid_from DATETIME(6) NOT NULL,
    valid_until DATETIME(6) NULL,
    CONSTRAINT fk_operation_restriction_operation FOREIGN KEY (operation_id) REFERENCES iam_operation(id),
    CONSTRAINT fk_operation_restriction_account FOREIGN KEY (account_id) REFERENCES user_account(id),
    CONSTRAINT chk_operation_restriction_status CHECK (status IN ('ACTIVE', 'REVOKED')),
    CONSTRAINT chk_operation_restriction_version CHECK (version >= 1),
    CONSTRAINT chk_operation_restriction_validity CHECK (valid_until IS NULL OR valid_until > valid_from),
    INDEX ix_operation_restriction (operation_id, category_key, account_id, status, valid_from, valid_until)
);

-- Editable capability seeds, not account grants or developer eligibility.
INSERT INTO iam_role VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), 'BASIC_CAPABILITIES', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_role VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), 'BASIC_USER', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_role VALUES (UUID_TO_BIN('395893c4-f238-57fe-861d-2592289a6b6e'), 'BASIC_GROUP_OWNER', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_role VALUES (UUID_TO_BIN('50b79280-16a6-5094-bea0-72a3ae325299'), 'BASIC_GROUP_MEMBER', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('0f07d0ae-9ff8-556a-b78c-d47d897b7d6d'), 'document-service', 'file.read', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('ec0b904d-ea1c-56a5-8a79-b6ce4d43cd5f'), 'document-service', 'file.read', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('a12b314d-66f9-547f-9dae-fe1e5bfebd20'), UUID_TO_BIN('ec0b904d-ea1c-56a5-8a79-b6ce4d43cd5f'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('a12b314d-66f9-547f-9dae-fe1e5bfebd20'), 'document-service', UUID_TO_BIN('0f07d0ae-9ff8-556a-b78c-d47d897b7d6d'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('0f07d0ae-9ff8-556a-b78c-d47d897b7d6d'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('0f07d0ae-9ff8-556a-b78c-d47d897b7d6d'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('9ef6cfa8-1257-5db6-98c1-95e2cb12e0e1'), 'document-service', 'file.download', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('ea05ae28-2449-54fb-b1cd-e8819952128e'), 'document-service', 'file.download', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('0373faa4-85e5-5062-8d82-f74cf20403ad'), UUID_TO_BIN('ea05ae28-2449-54fb-b1cd-e8819952128e'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('0373faa4-85e5-5062-8d82-f74cf20403ad'), 'document-service', UUID_TO_BIN('9ef6cfa8-1257-5db6-98c1-95e2cb12e0e1'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('9ef6cfa8-1257-5db6-98c1-95e2cb12e0e1'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('9ef6cfa8-1257-5db6-98c1-95e2cb12e0e1'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('245b3c80-a5e0-53c6-844b-288c753d9e8f'), 'document-service', 'file.create', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('c36d467b-e130-57a6-b1f6-0a45864e3f4d'), 'document-service', 'file.create', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('d5d1a810-8664-5da0-9ea2-6b2ef84ff1a9'), UUID_TO_BIN('c36d467b-e130-57a6-b1f6-0a45864e3f4d'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('d5d1a810-8664-5da0-9ea2-6b2ef84ff1a9'), 'document-service', UUID_TO_BIN('245b3c80-a5e0-53c6-844b-288c753d9e8f'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('245b3c80-a5e0-53c6-844b-288c753d9e8f'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('245b3c80-a5e0-53c6-844b-288c753d9e8f'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('407433be-4e89-53bd-a316-2ead79b395b8'), 'document-service', 'file.edit', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('15194624-ff9b-5100-a1ff-bfe72424fe49'), 'document-service', 'file.edit', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('6e8a6556-3b04-5fa1-8eb6-9ac8ee67dda7'), UUID_TO_BIN('15194624-ff9b-5100-a1ff-bfe72424fe49'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('6e8a6556-3b04-5fa1-8eb6-9ac8ee67dda7'), 'document-service', UUID_TO_BIN('407433be-4e89-53bd-a316-2ead79b395b8'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('407433be-4e89-53bd-a316-2ead79b395b8'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('407433be-4e89-53bd-a316-2ead79b395b8'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('f7b0fa45-ad35-5463-b10c-f96fe8630792'), 'document-service', 'file.collaborative.edit', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('f29464d7-81cb-5a17-bef3-9f609ea3d038'), 'document-service', 'file.collaborative.edit', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('2a07328a-58df-548d-b237-62d7d01a61d7'), UUID_TO_BIN('f29464d7-81cb-5a17-bef3-9f609ea3d038'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('2a07328a-58df-548d-b237-62d7d01a61d7'), 'document-service', UUID_TO_BIN('f7b0fa45-ad35-5463-b10c-f96fe8630792'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('f7b0fa45-ad35-5463-b10c-f96fe8630792'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('f7b0fa45-ad35-5463-b10c-f96fe8630792'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('521e2ff1-28ea-5169-bea6-85f00018ffb0'), 'document-service', 'file.copy', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('693fe340-7ad2-506c-bc01-7548fd3db228'), 'document-service', 'file.copy', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('44cdb161-2872-5d9e-a69d-1cec53865758'), UUID_TO_BIN('693fe340-7ad2-506c-bc01-7548fd3db228'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('44cdb161-2872-5d9e-a69d-1cec53865758'), 'document-service', UUID_TO_BIN('521e2ff1-28ea-5169-bea6-85f00018ffb0'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('521e2ff1-28ea-5169-bea6-85f00018ffb0'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('521e2ff1-28ea-5169-bea6-85f00018ffb0'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('b78d91ee-4e03-53ee-8626-6e18bf3e2a19'), 'document-service', 'file.move', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('140eff8a-0675-5552-af92-2f106b64d69c'), 'document-service', 'file.move', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('556a101a-78bb-5208-86ec-8a0f5d1715a3'), UUID_TO_BIN('140eff8a-0675-5552-af92-2f106b64d69c'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('556a101a-78bb-5208-86ec-8a0f5d1715a3'), 'document-service', UUID_TO_BIN('b78d91ee-4e03-53ee-8626-6e18bf3e2a19'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('b78d91ee-4e03-53ee-8626-6e18bf3e2a19'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('b78d91ee-4e03-53ee-8626-6e18bf3e2a19'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('9649dc85-0fe9-5cec-a6a3-030ce57a8913'), 'document-service', 'file.rename', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('ac761947-3fca-5350-af97-f21687b9d6af'), 'document-service', 'file.rename', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('e3cb697f-5da8-5f1e-9be4-6a6c62ddf0de'), UUID_TO_BIN('ac761947-3fca-5350-af97-f21687b9d6af'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('e3cb697f-5da8-5f1e-9be4-6a6c62ddf0de'), 'document-service', UUID_TO_BIN('9649dc85-0fe9-5cec-a6a3-030ce57a8913'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('9649dc85-0fe9-5cec-a6a3-030ce57a8913'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('9649dc85-0fe9-5cec-a6a3-030ce57a8913'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('d3a44a72-0e95-5a68-8e38-30ad91a02da3'), 'document-service', 'file.delete.schedule', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('df02fbbb-3701-5617-a539-25aaf4323bfa'), 'document-service', 'file.delete.schedule', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('3d841222-ca29-5215-bcea-2accb3c33188'), UUID_TO_BIN('df02fbbb-3701-5617-a539-25aaf4323bfa'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('3d841222-ca29-5215-bcea-2accb3c33188'), 'document-service', UUID_TO_BIN('d3a44a72-0e95-5a68-8e38-30ad91a02da3'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('d3a44a72-0e95-5a68-8e38-30ad91a02da3'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('d3a44a72-0e95-5a68-8e38-30ad91a02da3'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('3de4b4d2-fc67-53a2-913c-9c704714bb65'), 'document-service', 'file.restore', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('a67679fd-b9cb-5b06-880c-a31d6be48d4a'), 'document-service', 'file.restore', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('bb08b49b-c6bc-5600-bf48-50e71a7ba64e'), UUID_TO_BIN('a67679fd-b9cb-5b06-880c-a31d6be48d4a'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('bb08b49b-c6bc-5600-bf48-50e71a7ba64e'), 'document-service', UUID_TO_BIN('3de4b4d2-fc67-53a2-913c-9c704714bb65'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('3de4b4d2-fc67-53a2-913c-9c704714bb65'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('3de4b4d2-fc67-53a2-913c-9c704714bb65'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('f57c626e-73e0-549b-8e02-4cad5f0ff065'), 'document-service', 'file.share', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('dc3952b5-0bdc-581a-b0ac-43577d5978e2'), 'document-service', 'file.share', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('3fcfb013-57e5-56f8-a074-66173f6a3e72'), UUID_TO_BIN('dc3952b5-0bdc-581a-b0ac-43577d5978e2'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('3fcfb013-57e5-56f8-a074-66173f6a3e72'), 'document-service', UUID_TO_BIN('f57c626e-73e0-549b-8e02-4cad5f0ff065'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('f57c626e-73e0-549b-8e02-4cad5f0ff065'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('f57c626e-73e0-549b-8e02-4cad5f0ff065'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('09b69cb6-786d-5c6a-b7d4-a61fa640cd19'), 'document-service', 'file.share.view', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('99bf5ed9-bd69-520c-b456-3ca798cf6666'), 'document-service', 'file.share.view', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('e866f830-36f5-5c2f-bac6-3859939ccfab'), UUID_TO_BIN('99bf5ed9-bd69-520c-b456-3ca798cf6666'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('e866f830-36f5-5c2f-bac6-3859939ccfab'), 'document-service', UUID_TO_BIN('f57c626e-73e0-549b-8e02-4cad5f0ff065'), 1);
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('e866f830-36f5-5c2f-bac6-3859939ccfab'), 'document-service', UUID_TO_BIN('09b69cb6-786d-5c6a-b7d4-a61fa640cd19'), 2);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('09b69cb6-786d-5c6a-b7d4-a61fa640cd19'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('09b69cb6-786d-5c6a-b7d4-a61fa640cd19'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('cef2fea4-b096-52eb-a14e-215b81133c56'), 'document-service', 'file.share.edit', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('4dcfc8eb-8903-5003-b028-0fbb651be3aa'), 'document-service', 'file.share.edit', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('4b210543-3971-56d2-8003-f92da2a7196c'), UUID_TO_BIN('4dcfc8eb-8903-5003-b028-0fbb651be3aa'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('4b210543-3971-56d2-8003-f92da2a7196c'), 'document-service', UUID_TO_BIN('f57c626e-73e0-549b-8e02-4cad5f0ff065'), 1);
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('4b210543-3971-56d2-8003-f92da2a7196c'), 'document-service', UUID_TO_BIN('cef2fea4-b096-52eb-a14e-215b81133c56'), 2);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('cef2fea4-b096-52eb-a14e-215b81133c56'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('cef2fea4-b096-52eb-a14e-215b81133c56'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('d6b5cb82-13cb-5caa-aa8e-fec3b87a9b98'), 'document-service', 'file.share.revoke', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('1b5ea4cf-d36c-58e1-a3ce-5b493c1a99f3'), 'document-service', 'file.share.revoke', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('7ee99f60-9870-58c5-ba7f-724430564cf0'), UUID_TO_BIN('1b5ea4cf-d36c-58e1-a3ce-5b493c1a99f3'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('7ee99f60-9870-58c5-ba7f-724430564cf0'), 'document-service', UUID_TO_BIN('d6b5cb82-13cb-5caa-aa8e-fec3b87a9b98'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('d6b5cb82-13cb-5caa-aa8e-fec3b87a9b98'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('d6b5cb82-13cb-5caa-aa8e-fec3b87a9b98'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('db7e9ece-fe69-5089-9706-4ebf2ead6a1b'), 'document-service', 'content.access.update', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('1eabb76d-bb65-5e0e-a78c-cc71b7950d04'), 'document-service', 'content.access.update', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('49762299-5889-52c5-a820-1771032af4bd'), UUID_TO_BIN('1eabb76d-bb65-5e0e-a78c-cc71b7950d04'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('49762299-5889-52c5-a820-1771032af4bd'), 'document-service', UUID_TO_BIN('f57c626e-73e0-549b-8e02-4cad5f0ff065'), 1);
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('49762299-5889-52c5-a820-1771032af4bd'), 'document-service', UUID_TO_BIN('db7e9ece-fe69-5089-9706-4ebf2ead6a1b'), 2);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('db7e9ece-fe69-5089-9706-4ebf2ead6a1b'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('db7e9ece-fe69-5089-9706-4ebf2ead6a1b'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('3dc09690-357d-5e4e-a8a3-627bab0c255e'), 'document-service', 'folder.read', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('4417a9ca-7787-5f6b-a1bb-06f408518016'), 'document-service', 'folder.read', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('39b62375-24ca-5489-a37a-b9a296959d28'), UUID_TO_BIN('4417a9ca-7787-5f6b-a1bb-06f408518016'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('39b62375-24ca-5489-a37a-b9a296959d28'), 'document-service', UUID_TO_BIN('3dc09690-357d-5e4e-a8a3-627bab0c255e'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('3dc09690-357d-5e4e-a8a3-627bab0c255e'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('3dc09690-357d-5e4e-a8a3-627bab0c255e'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('27ffab28-558e-5be7-bc01-8c242cc974c4'), 'document-service', 'folder.create', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('37adaba8-5bf4-5439-b533-e285e1f9c5a1'), 'document-service', 'folder.create', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('c7d1b589-e07c-54c0-91e8-a7d51c3793c5'), UUID_TO_BIN('37adaba8-5bf4-5439-b533-e285e1f9c5a1'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('c7d1b589-e07c-54c0-91e8-a7d51c3793c5'), 'document-service', UUID_TO_BIN('27ffab28-558e-5be7-bc01-8c242cc974c4'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('27ffab28-558e-5be7-bc01-8c242cc974c4'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('27ffab28-558e-5be7-bc01-8c242cc974c4'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('3bea9591-1385-5122-9f6f-99c20d4c0c84'), 'document-service', 'folder.rename', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('9ddce8b1-9686-5f01-9c15-8ee020de9e54'), 'document-service', 'folder.rename', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('2409d037-be59-5e79-a4f1-278428aea620'), UUID_TO_BIN('9ddce8b1-9686-5f01-9c15-8ee020de9e54'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('2409d037-be59-5e79-a4f1-278428aea620'), 'document-service', UUID_TO_BIN('3bea9591-1385-5122-9f6f-99c20d4c0c84'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('3bea9591-1385-5122-9f6f-99c20d4c0c84'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('3bea9591-1385-5122-9f6f-99c20d4c0c84'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('19c535e3-d056-571d-a799-8cf3a4deb850'), 'document-service', 'folder.move', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('f4772b23-60e5-57ab-8bb0-0cbabc43e546'), 'document-service', 'folder.move', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('3abbfb61-78c0-5454-be37-ea75ad3043d6'), UUID_TO_BIN('f4772b23-60e5-57ab-8bb0-0cbabc43e546'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('3abbfb61-78c0-5454-be37-ea75ad3043d6'), 'document-service', UUID_TO_BIN('19c535e3-d056-571d-a799-8cf3a4deb850'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('19c535e3-d056-571d-a799-8cf3a4deb850'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('19c535e3-d056-571d-a799-8cf3a4deb850'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('4e40909d-1b05-536a-b155-cb9a5feecf83'), 'document-service', 'folder.copy', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('66c363c6-f7cc-51a0-86a2-12c40c915cf9'), 'document-service', 'folder.copy', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('ce12a0b0-46d6-528f-b2b0-4986b40c9c84'), UUID_TO_BIN('66c363c6-f7cc-51a0-86a2-12c40c915cf9'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('ce12a0b0-46d6-528f-b2b0-4986b40c9c84'), 'document-service', UUID_TO_BIN('4e40909d-1b05-536a-b155-cb9a5feecf83'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('4e40909d-1b05-536a-b155-cb9a5feecf83'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('4e40909d-1b05-536a-b155-cb9a5feecf83'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('72bcb34e-47c7-5b7c-a9b0-e9953f057464'), 'document-service', 'folder.delete.schedule', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('cbeb2ec2-d58f-5c21-a478-71c57eada5a5'), 'document-service', 'folder.delete.schedule', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('9e24c5c8-ec73-5a01-9d17-f3147266768d'), UUID_TO_BIN('cbeb2ec2-d58f-5c21-a478-71c57eada5a5'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('9e24c5c8-ec73-5a01-9d17-f3147266768d'), 'document-service', UUID_TO_BIN('72bcb34e-47c7-5b7c-a9b0-e9953f057464'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('72bcb34e-47c7-5b7c-a9b0-e9953f057464'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('72bcb34e-47c7-5b7c-a9b0-e9953f057464'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('7c2d9c8a-42fc-575f-8a84-756a9f72d89e'), 'document-service', 'folder.restore', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('db0a2e18-e404-5e1a-be59-f986d7edf576'), 'document-service', 'folder.restore', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('6800df09-ae40-54ad-8317-4696613339d3'), UUID_TO_BIN('db0a2e18-e404-5e1a-be59-f986d7edf576'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('6800df09-ae40-54ad-8317-4696613339d3'), 'document-service', UUID_TO_BIN('7c2d9c8a-42fc-575f-8a84-756a9f72d89e'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('7c2d9c8a-42fc-575f-8a84-756a9f72d89e'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('7c2d9c8a-42fc-575f-8a84-756a9f72d89e'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('1b3149b3-db5e-584e-9fa5-45a5f6e5aca8'), 'document-service', 'folder.share', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('600b6879-af16-5f3a-9441-b13c57d05a7a'), 'document-service', 'folder.share', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('0c69affa-61f2-5353-b8d6-72340c67fe0f'), UUID_TO_BIN('600b6879-af16-5f3a-9441-b13c57d05a7a'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('0c69affa-61f2-5353-b8d6-72340c67fe0f'), 'document-service', UUID_TO_BIN('f57c626e-73e0-549b-8e02-4cad5f0ff065'), 1);
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('0c69affa-61f2-5353-b8d6-72340c67fe0f'), 'document-service', UUID_TO_BIN('1b3149b3-db5e-584e-9fa5-45a5f6e5aca8'), 2);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('1b3149b3-db5e-584e-9fa5-45a5f6e5aca8'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('1b3149b3-db5e-584e-9fa5-45a5f6e5aca8'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('d0798579-4be5-59b4-aa31-67d175c8fc1a'), 'document-service', 'workspace.create', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('d7e41dc5-353d-558b-b7ae-382dc0542639'), 'document-service', 'workspace.create', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('78515ffd-941f-5068-a4b0-2c7f15f83691'), UUID_TO_BIN('d7e41dc5-353d-558b-b7ae-382dc0542639'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('78515ffd-941f-5068-a4b0-2c7f15f83691'), 'document-service', UUID_TO_BIN('d0798579-4be5-59b4-aa31-67d175c8fc1a'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('d0798579-4be5-59b4-aa31-67d175c8fc1a'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('d0798579-4be5-59b4-aa31-67d175c8fc1a'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('395dc600-be37-5f90-abda-db334ca1f79f'), 'document-service', 'workspace.read', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('1ec323fa-1b09-5941-85ee-b1f06673993c'), 'document-service', 'workspace.read', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('885b56fb-e19a-5240-81aa-facf046cc878'), UUID_TO_BIN('1ec323fa-1b09-5941-85ee-b1f06673993c'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('885b56fb-e19a-5240-81aa-facf046cc878'), 'document-service', UUID_TO_BIN('395dc600-be37-5f90-abda-db334ca1f79f'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('395dc600-be37-5f90-abda-db334ca1f79f'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('395dc600-be37-5f90-abda-db334ca1f79f'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('a4c0ff6d-514a-5386-b2bc-7fc214226fc6'), 'document-service', 'quota.read', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('fcaf4b32-6c5d-5af3-aff1-a11ee7a541f9'), 'document-service', 'quota.read', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('ea7d7605-d0f7-54b5-8875-b2749ba8de81'), UUID_TO_BIN('fcaf4b32-6c5d-5af3-aff1-a11ee7a541f9'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('ea7d7605-d0f7-54b5-8875-b2749ba8de81'), 'document-service', UUID_TO_BIN('a4c0ff6d-514a-5386-b2bc-7fc214226fc6'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('a4c0ff6d-514a-5386-b2bc-7fc214226fc6'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('a4c0ff6d-514a-5386-b2bc-7fc214226fc6'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('aaf813ba-ed52-5c65-9660-9b7fa6f7517e'), 'document-service', 'deletion.read', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('3f6757c8-6585-5e61-8f3c-30c80991eeef'), 'document-service', 'deletion.read', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('dd8ab465-d33b-5672-a0f8-bf348ace17cd'), UUID_TO_BIN('3f6757c8-6585-5e61-8f3c-30c80991eeef'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('dd8ab465-d33b-5672-a0f8-bf348ace17cd'), 'document-service', UUID_TO_BIN('aaf813ba-ed52-5c65-9660-9b7fa6f7517e'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('aaf813ba-ed52-5c65-9660-9b7fa6f7517e'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('aaf813ba-ed52-5c65-9660-9b7fa6f7517e'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('6b390113-de12-5cfd-a972-4ffdd3bb259a'), 'auth-service', 'group.create', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('df05370f-eda8-524a-90d4-dc13ce44fdcb'), 'auth-service', 'group.create', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('c39ae7a4-e1f4-5bbd-ad2f-e678bb655f55'), UUID_TO_BIN('df05370f-eda8-524a-90d4-dc13ce44fdcb'), 'auth-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('c39ae7a4-e1f4-5bbd-ad2f-e678bb655f55'), 'auth-service', UUID_TO_BIN('6b390113-de12-5cfd-a972-4ffdd3bb259a'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('6b390113-de12-5cfd-a972-4ffdd3bb259a'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('6b390113-de12-5cfd-a972-4ffdd3bb259a'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('6963c1e8-78a5-5b03-9456-f535097e5ca7'), 'auth-service', 'group.read', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('769218e9-8658-5566-9437-977a7015d568'), 'auth-service', 'group.read', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('e56d24ae-8078-59fb-a51f-0b1034f435c7'), UUID_TO_BIN('769218e9-8658-5566-9437-977a7015d568'), 'auth-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('e56d24ae-8078-59fb-a51f-0b1034f435c7'), 'auth-service', UUID_TO_BIN('6963c1e8-78a5-5b03-9456-f535097e5ca7'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('6963c1e8-78a5-5b03-9456-f535097e5ca7'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('6963c1e8-78a5-5b03-9456-f535097e5ca7'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('395893c4-f238-57fe-861d-2592289a6b6e'), UUID_TO_BIN('6963c1e8-78a5-5b03-9456-f535097e5ca7'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('50b79280-16a6-5094-bea0-72a3ae325299'), UUID_TO_BIN('6963c1e8-78a5-5b03-9456-f535097e5ca7'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('01082025-099f-5840-b7be-cddc2e4e2084'), 'auth-service', 'group.invitation.issue', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('bdbf5b1d-b33a-5c82-abf7-bbf31cf413c7'), 'auth-service', 'group.invitation.issue', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('8f7fc9ec-2d38-5c5d-9d3e-0d179d1d7eea'), UUID_TO_BIN('bdbf5b1d-b33a-5c82-abf7-bbf31cf413c7'), 'auth-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('8f7fc9ec-2d38-5c5d-9d3e-0d179d1d7eea'), 'auth-service', UUID_TO_BIN('01082025-099f-5840-b7be-cddc2e4e2084'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('01082025-099f-5840-b7be-cddc2e4e2084'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('395893c4-f238-57fe-861d-2592289a6b6e'), UUID_TO_BIN('01082025-099f-5840-b7be-cddc2e4e2084'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('3772dea0-3580-520d-83c0-2523210b969b'), 'auth-service', 'group.invitation.accept', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('c8a44ac7-02fe-5758-8457-e3f7ec1d93ef'), 'auth-service', 'group.invitation.accept', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('61a37b98-0978-5358-805f-133c26d24315'), UUID_TO_BIN('c8a44ac7-02fe-5758-8457-e3f7ec1d93ef'), 'auth-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('61a37b98-0978-5358-805f-133c26d24315'), 'auth-service', UUID_TO_BIN('3772dea0-3580-520d-83c0-2523210b969b'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('3772dea0-3580-520d-83c0-2523210b969b'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('3772dea0-3580-520d-83c0-2523210b969b'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('e5bf7d3a-763a-5e00-b499-ae2b008874e3'), 'auth-service', 'group.invitation.decline', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('f2c15d65-ef95-5b3f-bd45-0e9636f2e55a'), 'auth-service', 'group.invitation.decline', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('a4cd39c7-a6c0-5499-a758-8d8b4bc1b6b6'), UUID_TO_BIN('f2c15d65-ef95-5b3f-bd45-0e9636f2e55a'), 'auth-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('a4cd39c7-a6c0-5499-a758-8d8b4bc1b6b6'), 'auth-service', UUID_TO_BIN('e5bf7d3a-763a-5e00-b499-ae2b008874e3'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('e5bf7d3a-763a-5e00-b499-ae2b008874e3'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('e5bf7d3a-763a-5e00-b499-ae2b008874e3'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('96c4a9ae-c008-5836-94a3-23ba9576b2e0'), 'auth-service', 'group.invitation.revoke', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('15f196f5-198e-533f-9089-937d573094ea'), 'auth-service', 'group.invitation.revoke', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('6c4a532a-73ab-553c-a5dc-095183d31c43'), UUID_TO_BIN('15f196f5-198e-533f-9089-937d573094ea'), 'auth-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('6c4a532a-73ab-553c-a5dc-095183d31c43'), 'auth-service', UUID_TO_BIN('96c4a9ae-c008-5836-94a3-23ba9576b2e0'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('96c4a9ae-c008-5836-94a3-23ba9576b2e0'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('395893c4-f238-57fe-861d-2592289a6b6e'), UUID_TO_BIN('96c4a9ae-c008-5836-94a3-23ba9576b2e0'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('66c9bc1d-366a-5400-b387-be7e3d9bfcb3'), 'auth-service', 'group.member.remove', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('68ba46a0-cbfe-594a-b9e2-8659a17ee6e3'), 'auth-service', 'group.member.remove', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('7c2c9d82-fcfa-538a-84b0-5e51762d1513'), UUID_TO_BIN('68ba46a0-cbfe-594a-b9e2-8659a17ee6e3'), 'auth-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('7c2c9d82-fcfa-538a-84b0-5e51762d1513'), 'auth-service', UUID_TO_BIN('66c9bc1d-366a-5400-b387-be7e3d9bfcb3'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('66c9bc1d-366a-5400-b387-be7e3d9bfcb3'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('395893c4-f238-57fe-861d-2592289a6b6e'), UUID_TO_BIN('66c9bc1d-366a-5400-b387-be7e3d9bfcb3'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('02b75653-8051-52c2-b7ed-3215572e5cb0'), 'auth-service', 'group.leave', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('e0ea3049-a7c2-5e1d-8d1c-f9a95bc453b5'), 'auth-service', 'group.leave', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('ffb84d97-eb34-5e62-80c6-a13a358b909d'), UUID_TO_BIN('e0ea3049-a7c2-5e1d-8d1c-f9a95bc453b5'), 'auth-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('ffb84d97-eb34-5e62-80c6-a13a358b909d'), 'auth-service', UUID_TO_BIN('02b75653-8051-52c2-b7ed-3215572e5cb0'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('02b75653-8051-52c2-b7ed-3215572e5cb0'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('02b75653-8051-52c2-b7ed-3215572e5cb0'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('50b79280-16a6-5094-bea0-72a3ae325299'), UUID_TO_BIN('02b75653-8051-52c2-b7ed-3215572e5cb0'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('657b73c1-96af-565d-bb29-49fca690deea'), 'auth-service', 'group.delete.schedule', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('f3d8dd35-f0df-58bd-91a8-1b0a98dc7db2'), 'auth-service', 'group.delete.schedule', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('ee1a22c1-9274-5d0f-8eb1-ae2d23116939'), UUID_TO_BIN('f3d8dd35-f0df-58bd-91a8-1b0a98dc7db2'), 'auth-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('ee1a22c1-9274-5d0f-8eb1-ae2d23116939'), 'auth-service', UUID_TO_BIN('657b73c1-96af-565d-bb29-49fca690deea'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('657b73c1-96af-565d-bb29-49fca690deea'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('395893c4-f238-57fe-861d-2592289a6b6e'), UUID_TO_BIN('657b73c1-96af-565d-bb29-49fca690deea'));
INSERT INTO iam_stakeholder_role_binding VALUES ('INDIVIDUAL', UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_context_member_role_binding VALUES ('INDIVIDUAL', UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), 'ACTIVE', 1);
INSERT INTO iam_group_relationship_role_binding VALUES ('OWNER',UUID_TO_BIN('395893c4-f238-57fe-861d-2592289a6b6e'),'ACTIVE',1);
INSERT INTO iam_group_relationship_role_binding VALUES ('MEMBER',UUID_TO_BIN('50b79280-16a6-5094-bea0-72a3ae325299'),'ACTIVE',1);
