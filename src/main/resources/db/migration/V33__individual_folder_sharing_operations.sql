-- Folder invitation modes are registered independently of file operations.
-- View/edit issuance also requires the general folder sharing capability.
INSERT INTO iam_authority VALUES (UUID_TO_BIN('c5bdc677-a923-54b9-9159-99db7bf2a0e1'), 'document-service', 'folder.share.view', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('0013ba1f-2f6a-53d0-9ed8-3dd726ecfce5'), 'document-service', 'folder.share.view', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('45b05397-bd1d-5a29-9a5d-7e4cb19f3d26'), UUID_TO_BIN('0013ba1f-2f6a-53d0-9ed8-3dd726ecfce5'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('45b05397-bd1d-5a29-9a5d-7e4cb19f3d26'), 'document-service', UUID_TO_BIN('c5bdc677-a923-54b9-9159-99db7bf2a0e1'), 1);
INSERT INTO iam_policy_authority SELECT UUID_TO_BIN('45b05397-bd1d-5a29-9a5d-7e4cb19f3d26'), 'document-service', id, 2 FROM iam_authority WHERE service_id='document-service' AND authority_key='folder.share';
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('c5bdc677-a923-54b9-9159-99db7bf2a0e1'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('c5bdc677-a923-54b9-9159-99db7bf2a0e1'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('53444c69-3a24-5e59-bb6c-24ee1a88d914'), 'document-service', 'folder.share.edit', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('01f93354-b201-57af-b564-eccb74e811e0'), 'document-service', 'folder.share.edit', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('9a8c5f10-eb03-5796-b2d8-84db37c041e6'), UUID_TO_BIN('01f93354-b201-57af-b564-eccb74e811e0'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('9a8c5f10-eb03-5796-b2d8-84db37c041e6'), 'document-service', UUID_TO_BIN('53444c69-3a24-5e59-bb6c-24ee1a88d914'), 1);
INSERT INTO iam_policy_authority SELECT UUID_TO_BIN('9a8c5f10-eb03-5796-b2d8-84db37c041e6'), 'document-service', id, 2 FROM iam_authority WHERE service_id='document-service' AND authority_key='folder.share';
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('53444c69-3a24-5e59-bb6c-24ee1a88d914'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('53444c69-3a24-5e59-bb6c-24ee1a88d914'));
INSERT INTO iam_authority VALUES (UUID_TO_BIN('5c4eaf7e-383d-5d0b-9c61-af00ca9aafbb'), 'document-service', 'folder.share.revoke', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation VALUES (UUID_TO_BIN('0338738a-3024-5110-a9e9-6425d4b2880c'), 'document-service', 'folder.share.revoke', 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_operation_policy VALUES (UUID_TO_BIN('37be07ad-88ec-56c7-8958-e0f5fc8c1842'), UUID_TO_BIN('0338738a-3024-5110-a9e9-6425d4b2880c'), 'document-service', 'ALL_OF', FALSE, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
INSERT INTO iam_policy_authority VALUES (UUID_TO_BIN('37be07ad-88ec-56c7-8958-e0f5fc8c1842'), 'document-service', UUID_TO_BIN('5c4eaf7e-383d-5d0b-9c61-af00ca9aafbb'), 1);
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'), UUID_TO_BIN('5c4eaf7e-383d-5d0b-9c61-af00ca9aafbb'));
INSERT INTO iam_role_authority VALUES (UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'), UUID_TO_BIN('5c4eaf7e-383d-5d0b-9c61-af00ca9aafbb'));
UPDATE iam_role SET version=version+1,updated_at=UTC_TIMESTAMP(6) WHERE id IN (UUID_TO_BIN('c683af7e-fb11-5d2b-9562-fc28b5d9cfc3'),UUID_TO_BIN('08f9b2ce-d2ae-58d9-837b-64131fed8862'));
UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL';
