-- Editable IAM development seed for the synthetic Phase 1 actors.
-- Run only after Flyway has created an empty auth_service_test_app schema.
-- Example: mysql auth_service_test_app < provision/user_init.sql
-- This data-only script uses INSERT IGNORE for safe repeated execution on that empty test schema.
-- It does not restore sessions, refresh tokens, or audit history; authenticate after seeding.
-- Document workspace ACLs live in the separate Document service database and depend on workspace rows.
-- Password hashes are included in login_identity rows; plaintext passwords and signing keys are not.

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT  IGNORE INTO `users` (`id`, `display_name`, `status`, `last_login_at`, `created_at`, `updated_at`) VALUES (_binary '\'�Y�\'\�O^�\�K\�͟�','Phase One Alice','ACTIVE','2026-10-15 19:50:29.822209','2026-10-15 02:29:46.726738','2026-10-15 19:50:29.822209');
INSERT  IGNORE INTO `users` (`id`, `display_name`, `status`, `last_login_at`, `created_at`, `updated_at`) VALUES (_binary '(\�x��F\�\�\�|R\�','Phase One Carol','ACTIVE','2026-10-15 19:50:31.298308','2026-10-15 02:29:54.731987','2026-10-15 19:50:31.298308');
INSERT  IGNORE INTO `users` (`id`, `display_name`, `status`, `last_login_at`, `created_at`, `updated_at`) VALUES (_binary 'Mz7�nL硨׋�\�','Phase One Mallory','ACTIVE','2026-10-15 19:50:32.140242','2026-10-15 02:29:59.548166','2026-10-15 19:50:32.140242');
INSERT  IGNORE INTO `users` (`id`, `display_name`, `status`, `last_login_at`, `created_at`, `updated_at`) VALUES (_binary '�)}4:\�Al�K\�Y\�S0j','Phase One Bob','ACTIVE','2026-10-15 19:50:30.593587','2026-10-15 02:29:50.500660','2026-10-15 19:50:30.593587');
INSERT  IGNORE INTO `users` (`id`, `display_name`, `status`, `last_login_at`, `created_at`, `updated_at`) VALUES (_binary '\�\�F�N���c6���','Phase One Developer','ACTIVE','2026-10-15 18:52:04.287870','2026-10-15 02:29:41.842921','2026-10-15 18:52:04.287870');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;

/*!40000 ALTER TABLE `user_profile` DISABLE KEYS */;
INSERT  IGNORE INTO `user_profile` (`user_id`, `first_name`, `middle_name`, `last_name`, `date_of_birth`, `profile_image_key`, `locale`, `time_zone`, `updated_at`) VALUES (_binary '\'�Y�\'\�O^�\�K\�͟�',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'2026-10-15 02:29:46.726738');
INSERT  IGNORE INTO `user_profile` (`user_id`, `first_name`, `middle_name`, `last_name`, `date_of_birth`, `profile_image_key`, `locale`, `time_zone`, `updated_at`) VALUES (_binary '(\�x��F\�\�\�|R\�',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'2026-10-15 02:29:54.731987');
INSERT  IGNORE INTO `user_profile` (`user_id`, `first_name`, `middle_name`, `last_name`, `date_of_birth`, `profile_image_key`, `locale`, `time_zone`, `updated_at`) VALUES (_binary 'Mz7�nL硨׋�\�',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'2026-10-15 02:29:59.548166');
INSERT  IGNORE INTO `user_profile` (`user_id`, `first_name`, `middle_name`, `last_name`, `date_of_birth`, `profile_image_key`, `locale`, `time_zone`, `updated_at`) VALUES (_binary '�)}4:\�Al�K\�Y\�S0j',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'2026-10-15 02:29:50.500660');
INSERT  IGNORE INTO `user_profile` (`user_id`, `first_name`, `middle_name`, `last_name`, `date_of_birth`, `profile_image_key`, `locale`, `time_zone`, `updated_at`) VALUES (_binary '\�\�F�N���c6���',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'2026-10-15 02:29:41.842921');
/*!40000 ALTER TABLE `user_profile` ENABLE KEYS */;

/*!40000 ALTER TABLE `user_contact` DISABLE KEYS */;
INSERT  IGNORE INTO `user_contact` (`id`, `user_id`, `type`, `value`, `is_primary`, `verified`, `verified_at`, `created_at`) VALUES (_binary '\r\\�챐@b��cnd	',_binary 'Mz7�nL硨׋�\�','EMAIL','phase1.mallory.6eeee93364034c5eb3a03f09547beb02@example.test',1,1,'2026-10-15 02:29:59.157968','2026-10-15 02:29:59.548166');
INSERT  IGNORE INTO `user_contact` (`id`, `user_id`, `type`, `value`, `is_primary`, `verified`, `verified_at`, `created_at`) VALUES (_binary '(*].�L���\�q~W�!',_binary '\�\�F�N���c6���','EMAIL','phase1.developer.6eeee93364034c5eb3a03f09547beb02@example.test',1,1,'2026-10-15 02:29:41.380007','2026-10-15 02:29:41.842921');
INSERT  IGNORE INTO `user_contact` (`id`, `user_id`, `type`, `value`, `is_primary`, `verified`, `verified_at`, `created_at`) VALUES (_binary '�\�Ч��LՓ\�Fw�\�',_binary '\'�Y�\'\�O^�\�K\�͟�','EMAIL','phase1.alice.6eeee93364034c5eb3a03f09547beb02@example.test',1,1,'2026-10-15 02:29:46.281114','2026-10-15 02:29:46.726738');
INSERT  IGNORE INTO `user_contact` (`id`, `user_id`, `type`, `value`, `is_primary`, `verified`, `verified_at`, `created_at`) VALUES (_binary '\�\�O[K4B끠I\�}(\�',_binary '�)}4:\�Al�K\�Y\�S0j','EMAIL','phase1.bob.6eeee93364034c5eb3a03f09547beb02@example.test',1,1,'2026-10-15 02:29:50.145394','2026-10-15 02:29:50.500660');
INSERT  IGNORE INTO `user_contact` (`id`, `user_id`, `type`, `value`, `is_primary`, `verified`, `verified_at`, `created_at`) VALUES (_binary 'ܻ�!-KH?�Y-\��mT�',_binary '(\�x��F\�\�\�|R\�','EMAIL','phase1.carol.6eeee93364034c5eb3a03f09547beb02@example.test',1,1,'2026-10-15 02:29:54.181844','2026-10-15 02:29:54.731987');
/*!40000 ALTER TABLE `user_contact` ENABLE KEYS */;

/*!40000 ALTER TABLE `user_account` DISABLE KEYS */;
INSERT  IGNORE INTO `user_account` (`id`, `user_id`, `type`, `display_name`, `status`, `created_at`, `updated_at`, `organization_id`, `lifecycle_version`, `removed_at`, `retain_until`, `purged_at`, `blacklist_until`, `restriction_id`) VALUES (_binary ' �$}X\�F\'�g��WO�',_binary 'Mz7�nL硨׋�\�','PERSONAL','Phase One Mallory','ACTIVE','2026-10-15 02:29:59.548166','2026-10-15 02:29:59.548166',NULL,1,NULL,NULL,NULL,NULL,NULL);
INSERT  IGNORE INTO `user_account` (`id`, `user_id`, `type`, `display_name`, `status`, `created_at`, `updated_at`, `organization_id`, `lifecycle_version`, `removed_at`, `retain_until`, `purged_at`, `blacklist_until`, `restriction_id`) VALUES (_binary '�6\�{c�L��l�#�J\�\�',_binary '�)}4:\�Al�K\�Y\�S0j','PERSONAL','Phase One Bob','ACTIVE','2026-10-15 02:29:50.500660','2026-10-15 02:29:50.500660',NULL,1,NULL,NULL,NULL,NULL,NULL);
INSERT  IGNORE INTO `user_account` (`id`, `user_id`, `type`, `display_name`, `status`, `created_at`, `updated_at`, `organization_id`, `lifecycle_version`, `removed_at`, `retain_until`, `purged_at`, `blacklist_until`, `restriction_id`) VALUES (_binary '�(o{a�DΜ\�\�&�\��',_binary '(\�x��F\�\�\�|R\�','PERSONAL','Phase One Carol','ACTIVE','2026-10-15 02:29:54.731987','2026-10-15 02:29:54.731987',NULL,1,NULL,NULL,NULL,NULL,NULL);
INSERT  IGNORE INTO `user_account` (`id`, `user_id`, `type`, `display_name`, `status`, `created_at`, `updated_at`, `organization_id`, `lifecycle_version`, `removed_at`, `retain_until`, `purged_at`, `blacklist_until`, `restriction_id`) VALUES (_binary '��v�N\r�;o� h�<',_binary '\'�Y�\'\�O^�\�K\�͟�','PERSONAL','Phase One Alice','ACTIVE','2026-10-15 02:29:46.726738','2026-10-15 02:29:46.726738',NULL,1,NULL,NULL,NULL,NULL,NULL);
INSERT  IGNORE INTO `user_account` (`id`, `user_id`, `type`, `display_name`, `status`, `created_at`, `updated_at`, `organization_id`, `lifecycle_version`, `removed_at`, `retain_until`, `purged_at`, `blacklist_until`, `restriction_id`) VALUES (_binary '\�\�KQZL\�\�e0�M',_binary '\�\�F�N���c6���','PERSONAL','Phase One Developer','ACTIVE','2026-10-15 02:29:41.842921','2026-10-15 02:29:41.842921',NULL,1,NULL,NULL,NULL,NULL,NULL);
/*!40000 ALTER TABLE `user_account` ENABLE KEYS */;

/*!40000 ALTER TABLE `user_preference` DISABLE KEYS */;
INSERT  IGNORE INTO `user_preference` (`user_id`, `preferred_account_id`, `theme`, `locale`, `time_zone`, `email_notifications`, `push_notifications`, `security_notifications`, `updated_at`) VALUES (_binary '\'�Y�\'\�O^�\�K\�͟�',_binary '��v�N\r�;o� h�<','SYSTEM',NULL,'UTC',0,0,1,'2026-10-15 02:29:46.726738');
INSERT  IGNORE INTO `user_preference` (`user_id`, `preferred_account_id`, `theme`, `locale`, `time_zone`, `email_notifications`, `push_notifications`, `security_notifications`, `updated_at`) VALUES (_binary '(\�x��F\�\�\�|R\�',_binary '�(o{a�DΜ\�\�&�\��','SYSTEM',NULL,'UTC',0,0,1,'2026-10-15 02:29:54.731987');
INSERT  IGNORE INTO `user_preference` (`user_id`, `preferred_account_id`, `theme`, `locale`, `time_zone`, `email_notifications`, `push_notifications`, `security_notifications`, `updated_at`) VALUES (_binary 'Mz7�nL硨׋�\�',_binary ' �$}X\�F\'�g��WO�','SYSTEM',NULL,'UTC',0,0,1,'2026-10-15 02:29:59.548166');
INSERT  IGNORE INTO `user_preference` (`user_id`, `preferred_account_id`, `theme`, `locale`, `time_zone`, `email_notifications`, `push_notifications`, `security_notifications`, `updated_at`) VALUES (_binary '�)}4:\�Al�K\�Y\�S0j',_binary '�6\�{c�L��l�#�J\�\�','SYSTEM',NULL,'UTC',0,0,1,'2026-10-15 02:29:50.500660');
INSERT  IGNORE INTO `user_preference` (`user_id`, `preferred_account_id`, `theme`, `locale`, `time_zone`, `email_notifications`, `push_notifications`, `security_notifications`, `updated_at`) VALUES (_binary '\�\�F�N���c6���',_binary '\�\�KQZL\�\�e0�M','SYSTEM',NULL,'UTC',0,0,1,'2026-10-15 02:29:41.842921');
/*!40000 ALTER TABLE `user_preference` ENABLE KEYS */;

/*!40000 ALTER TABLE `login_identity` DISABLE KEYS */;
INSERT  IGNORE INTO `login_identity` (`id`, `account_id`, `type`, `identifier`, `password_hash`, `external_subject`, `status`, `credential_version`, `last_authenticated_at`, `created_at`, `updated_at`, `lifecycle_attempts`, `lifecycle_locked_until`) VALUES (_binary '0Z3�fA��²F�BQS',_binary '\�\�KQZL\�\�e0�M','EMAIL','phase1.developer.6eeee93364034c5eb3a03f09547beb02@example.test','b6f4a0627682e4e2723984c19bf7cf4c69f1a1b412ff9ead071335682bf9115cb4be7f599a44362a4ea7b4d324eebbff',NULL,'ACTIVE',1,'2026-10-15 18:52:04.287870','2026-10-15 02:29:41.842921','2026-10-15 18:52:04.287870',0,NULL);
INSERT  IGNORE INTO `login_identity` (`id`, `account_id`, `type`, `identifier`, `password_hash`, `external_subject`, `status`, `credential_version`, `last_authenticated_at`, `created_at`, `updated_at`, `lifecycle_attempts`, `lifecycle_locked_until`) VALUES (_binary 'Q�&i�I��\�p�{f|C',_binary ' �$}X\�F\'�g��WO�','EMAIL','phase1.mallory.6eeee93364034c5eb3a03f09547beb02@example.test','2b1d3c11c05bc860f107425d9415d1e02a56cbacf5bb05c47dbdeae4243b7d3322398eb156b690d809e1f5968015733d',NULL,'ACTIVE',1,'2026-10-15 19:50:32.140242','2026-10-15 02:29:59.548166','2026-10-15 19:50:32.140242',0,NULL);
INSERT  IGNORE INTO `login_identity` (`id`, `account_id`, `type`, `identifier`, `password_hash`, `external_subject`, `status`, `credential_version`, `last_authenticated_at`, `created_at`, `updated_at`, `lifecycle_attempts`, `lifecycle_locked_until`) VALUES (_binary 'e\��\�XD�?�-g�\�',_binary '��v�N\r�;o� h�<','EMAIL','phase1.alice.6eeee93364034c5eb3a03f09547beb02@example.test','c714cd18e020de99c01bab0cf051d845ebf764e1999d499353539c0e86cc7f44ca2481d55f68d30ba5ea64d0219a23a7',NULL,'ACTIVE',1,'2026-10-15 19:50:29.822209','2026-10-15 02:29:46.726738','2026-10-15 19:50:29.822209',0,NULL);
INSERT  IGNORE INTO `login_identity` (`id`, `account_id`, `type`, `identifier`, `password_hash`, `external_subject`, `status`, `credential_version`, `last_authenticated_at`, `created_at`, `updated_at`, `lifecycle_attempts`, `lifecycle_locked_until`) VALUES (_binary '�\�Kg�C���z��',_binary '�6\�{c�L��l�#�J\�\�','EMAIL','phase1.bob.6eeee93364034c5eb3a03f09547beb02@example.test','dbf8d1f2ab4cbf3fc95cef1bb9084768602b7caef6c216a6800e856cffe4c8a2a6b40dec03c7af14b5f85756d5b9d71e',NULL,'ACTIVE',1,'2026-10-15 19:50:30.593587','2026-10-15 02:29:50.500660','2026-10-15 19:50:30.593587',0,NULL);
INSERT  IGNORE INTO `login_identity` (`id`, `account_id`, `type`, `identifier`, `password_hash`, `external_subject`, `status`, `credential_version`, `last_authenticated_at`, `created_at`, `updated_at`, `lifecycle_attempts`, `lifecycle_locked_until`) VALUES (_binary '\�P5S�\�AՂ�4r�mb�',_binary '�(o{a�DΜ\�\�&�\��','EMAIL','phase1.carol.6eeee93364034c5eb3a03f09547beb02@example.test','fc552191cdcb5709c364d900534b4f1a921d79f5d2ade678614e66609dfa1d9ef86eb3bdc6a9a0ee0c7b09f48c5e041e',NULL,'ACTIVE',1,'2026-10-15 19:50:31.298308','2026-10-15 02:29:54.731987','2026-10-15 19:50:31.298308',0,NULL);
/*!40000 ALTER TABLE `login_identity` ENABLE KEYS */;

/*!40000 ALTER TABLE `account_group` DISABLE KEYS */;
INSERT  IGNORE INTO `account_group` (`id`, `user_id`, `status`, `created_at`, `updated_at`) VALUES (_binary '\�)�g@/�\�4\����',_binary '\�\�F�N���c6���','ACTIVE','2026-10-15 02:29:41.842921','2026-10-15 02:29:41.842921');
INSERT  IGNORE INTO `account_group` (`id`, `user_id`, `status`, `created_at`, `updated_at`) VALUES (_binary '�����\�C8�Ѻ\�\�ŗO',_binary '(\�x��F\�\�\�|R\�','ACTIVE','2026-10-15 02:29:54.731987','2026-10-15 02:29:54.731987');
INSERT  IGNORE INTO `account_group` (`id`, `user_id`, `status`, `created_at`, `updated_at`) VALUES (_binary '�S\�M��xD\\k=',_binary '�)}4:\�Al�K\�Y\�S0j','ACTIVE','2026-10-15 02:29:50.500660','2026-10-15 02:29:50.500660');
INSERT  IGNORE INTO `account_group` (`id`, `user_id`, `status`, `created_at`, `updated_at`) VALUES (_binary '�[\0\��Jǖ���	\�',_binary '\'�Y�\'\�O^�\�K\�͟�','ACTIVE','2026-10-15 02:29:46.726738','2026-10-15 02:29:46.726738');
INSERT  IGNORE INTO `account_group` (`id`, `user_id`, `status`, `created_at`, `updated_at`) VALUES (_binary '\�H�\��-E#��\�߫\�\�',_binary 'Mz7�nL硨׋�\�','ACTIVE','2026-10-15 02:29:59.548166','2026-10-15 02:29:59.548166');
/*!40000 ALTER TABLE `account_group` ENABLE KEYS */;

/*!40000 ALTER TABLE `account_group_member` DISABLE KEYS */;
INSERT  IGNORE INTO `account_group_member` (`account_id`, `account_group_id`, `status`, `link_method`, `linked_by_account_id`, `linked_at`, `disconnected_at`) VALUES (_binary ' �$}X\�F\'�g��WO�',_binary '\�H�\��-E#��\�߫\�\�','LINKED','REGISTRATION',_binary ' �$}X\�F\'�g��WO�','2026-10-15 02:29:59.548166',NULL);
INSERT  IGNORE INTO `account_group_member` (`account_id`, `account_group_id`, `status`, `link_method`, `linked_by_account_id`, `linked_at`, `disconnected_at`) VALUES (_binary '�6\�{c�L��l�#�J\�\�',_binary '�S\�M��xD\\k=','LINKED','REGISTRATION',_binary '�6\�{c�L��l�#�J\�\�','2026-10-15 02:29:50.500660',NULL);
INSERT  IGNORE INTO `account_group_member` (`account_id`, `account_group_id`, `status`, `link_method`, `linked_by_account_id`, `linked_at`, `disconnected_at`) VALUES (_binary '�(o{a�DΜ\�\�&�\��',_binary '�����\�C8�Ѻ\�\�ŗO','LINKED','REGISTRATION',_binary '�(o{a�DΜ\�\�&�\��','2026-10-15 02:29:54.731987',NULL);
INSERT  IGNORE INTO `account_group_member` (`account_id`, `account_group_id`, `status`, `link_method`, `linked_by_account_id`, `linked_at`, `disconnected_at`) VALUES (_binary '��v�N\r�;o� h�<',_binary '�[\0\��Jǖ���	\�','LINKED','REGISTRATION',_binary '��v�N\r�;o� h�<','2026-10-15 02:29:46.726738',NULL);
INSERT  IGNORE INTO `account_group_member` (`account_id`, `account_group_id`, `status`, `link_method`, `linked_by_account_id`, `linked_at`, `disconnected_at`) VALUES (_binary '\�\�KQZL\�\�e0�M',_binary '\�)�g@/�\�4\����','LINKED','REGISTRATION',_binary '\�\�KQZL\�\�e0�M','2026-10-15 02:29:41.842921',NULL);
/*!40000 ALTER TABLE `account_group_member` ENABLE KEYS */;

/*!40000 ALTER TABLE `iam_developer_eligibility` DISABLE KEYS */;
INSERT  IGNORE INTO `iam_developer_eligibility` (`account_id`, `status`, `version`, `provisioned_by`, `reason`, `failed_attempts`, `proof_window_at`, `updated_at`) VALUES (_binary '\�\�KQZL\�\�e0�M','ACTIVE',1,'local-platform-owner-phase1-acceptance','User-authorized isolated developer role-manager acceptance',0,'2026-10-15 18:52:20.104671','2026-10-15 02:31:12.651238');
/*!40000 ALTER TABLE `iam_developer_eligibility` ENABLE KEYS */;

/*!40000 ALTER TABLE `iam_group` DISABLE KEYS */;
INSERT  IGNORE INTO `iam_group` (`id`, `organization_id`, `parent_group_id`, `name`, `type`, `status`, `version`, `created_by_account_id`, `creation_request_id`, `creation_fingerprint`, `created_at`, `updated_at`, `workspace_context`, `purge_after`, `deletion_requested_at`, `deletion_notice_seconds`, `deletion_notice_batch_id`) VALUES (_binary '!n-\�\�@���*ő�̜',NULL,NULL,'Phase1 UAT 6eeee933','CUSTOM','ACTIVE',5,_binary '��v�N\r�;o� h�<',_binary '\�\\l�fUT]�x\��D\�','bf390ec2c53369626b7e0ca5efeb92c56d2e40ad61132bf4e4fc1595adf5d523','2026-10-15 03:01:53.924846','2026-10-15 18:51:00.876606','INDIVIDUAL',NULL,NULL,604800,NULL);
/*!40000 ALTER TABLE `iam_group` ENABLE KEYS */;

/*!40000 ALTER TABLE `personal_group_member` DISABLE KEYS */;
INSERT  IGNORE INTO `personal_group_member` (`group_id`, `account_id`, `id`, `workspace_context`, `status`, `version`, `joined_at`, `revoked_at`) VALUES (_binary '!n-\�\�@���*ő�̜',_binary '�6\�{c�L��l�#�J\�\�',_binary 'i��\���M<�<�]�\�<','INDIVIDUAL','ACTIVE',1,'2026-10-15 18:50:59.521232',NULL);
INSERT  IGNORE INTO `personal_group_member` (`group_id`, `account_id`, `id`, `workspace_context`, `status`, `version`, `joined_at`, `revoked_at`) VALUES (_binary '!n-\�\�@���*ő�̜',_binary '�(o{a�DΜ\�\�&�\��',_binary '�Ժ!\r\�O\�tp&\�Jx\�','INDIVIDUAL','ACTIVE',1,'2026-10-15 18:51:00.876606',NULL);
INSERT  IGNORE INTO `personal_group_member` (`group_id`, `account_id`, `id`, `workspace_context`, `status`, `version`, `joined_at`, `revoked_at`) VALUES (_binary '!n-\�\�@���*ő�̜',_binary '��v�N\r�;o� h�<',_binary '���BչH��\�`�\�\"Y\r','INDIVIDUAL','ACTIVE',1,'2026-10-15 03:01:53.924846',NULL);
/*!40000 ALTER TABLE `personal_group_member` ENABLE KEYS */;

/*!40000 ALTER TABLE `personal_group_invitation` DISABLE KEYS */;
INSERT  IGNORE INTO `personal_group_invitation` (`id`, `group_id`, `workspace_context`, `sender_account_id`, `recipient_account_id`, `status`, `version`, `creation_request_id`, `created_at`, `expires_at`, `responded_at`) VALUES (_binary '\�|�	D\�V\"\�Ftq',_binary '!n-\�\�@���*ő�̜','INDIVIDUAL',_binary '��v�N\r�;o� h�<',_binary '�(o{a�DΜ\�\�&�\��','ACCEPTED',2,_binary 'i�\�To}W��=,�8\�','2026-10-15 03:01:54.444232','2026-10-22 03:01:54.444232','2026-10-15 18:51:00.876606');
INSERT  IGNORE INTO `personal_group_invitation` (`id`, `group_id`, `workspace_context`, `sender_account_id`, `recipient_account_id`, `status`, `version`, `creation_request_id`, `created_at`, `expires_at`, `responded_at`) VALUES (_binary '�iWA?DO��\�\�G\�\�',_binary '!n-\�\�@���*ő�̜','INDIVIDUAL',_binary '��v�N\r�;o� h�<',_binary '�6\�{c�L��l�#�J\�\�','ACCEPTED',2,_binary '�P\�j\�P#�+sa��o','2026-10-15 03:01:54.121952','2026-10-22 03:01:54.121952','2026-10-15 18:50:59.521232');
/*!40000 ALTER TABLE `personal_group_invitation` ENABLE KEYS */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;


-- Catalog/policy definitions are migration-owned; inspect after import:
SELECT COUNT(*) AS active_operations FROM auth_service_test_app.iam_operation WHERE status='ACTIVE';
SELECT COUNT(*) AS active_policies FROM auth_service_test_app.iam_operation_policy WHERE status='ACTIVE';



