# Drive Platform — Project Specification

## SpiceDB authorization migration target — 17 October 2026

The agreed target introduces internal SpiceDB permission evaluation incrementally, starting with organization/professional management and later organization content, individual/basic and student/institutional contexts. [SpiceDB security requirements change](docs/SPICEDB_SECURITY_REQUIREMENTS_CHANGE.md) defines responsibilities, rollout gates, consistency/fencing, Redis retention and dedicated developer/organization ACL UI requirements. This amendment records the target; it does not claim implementation or authorize removal of current enforcement before validation.

Local development currently runs SpiceDB v1.56.2 by immutable image digest on the private integrated Compose network. It uses the existing MySQL 8.4 service with a dedicated `spicedb_authz` database and `spicedb_runtime` account; the existing `mysql-data` volume provides persistence. The gRPC key and database credential stay in ignored Auth `.secrets` files. Plaintext gRPC is restricted to local dev/test network use; Auth production integration remains disabled until transport TLS, HA, backup and operational controls are selected and verified. This local setup does not make a production datastore decision.

The open-source SpiceDB image authenticates preshared keys but does not scope API methods per key. Auth therefore connects through the internal `spicedb-api-gateway`: the check credential can only call schema-approved `CheckPermission`, while an optional, distinct projection credential can only call bounded `WriteRelationships` for allowlisted organization tuple types and relations. Projection writes allow idempotent TOUCH or exact-tuple DELETE batches only; they reject caveats, expirations, preconditions, transaction metadata and batches over 1,000. The projection credential is not configured by default and must be held only by a projection worker. The gateway forwards accepted calls with a backend credential held only by that gateway. The schema operator remains a separate explicit one-shot service with its own unrestricted SpiceDB credential. Any API method or permission expansion must have positive and negative tests; keep backend/operator credentials out of application containers and keep the SpiceDB endpoint private.

For migrated operations, fresh IAM identity/session/account eligibility, current required-versus-applied authorization revisions, SpiceDB permission checks and owning-service resource guards jointly determine access. MySQL remains authoritative for business facts, catalog identities, lifecycle, audit and outbox; owning services project necessary relationships into SpiceDB. Projection lag must deny sensitive access through a current authoritative fence. ZedTokens describe committed SpiceDB state and do not cover unpublished events. Organization/global revocations must constrain descendants even when their old resource tokens are unchanged. No legacy-or-SpiceDB allow fallback is permitted.

Organization shadow projection is rebuilt from Auth MySQL snapshots. The source mutation and its transactional outbox event advance a durable required revision in the same transaction; a bounded worker backfills missing organizations, serializes writes per organization outside SQL transactions, applies idempotent tuple deltas, and acknowledges only when the required revision is unchanged. A durable exact-tuple ledger supports retries and source reconciliation. Global IAM policy changes fence all organizations, and future/expiring assignments and restrictions schedule a reprojection boundary. The worker stays disabled until a separate projection credential is provisioned for the intended environment.

The older Caffeine/Redis authorization lookup design is superseded only for explicitly migrated contexts/operations. Redis remains responsible for distributed rate limits and brute-force protection; unmigrated authorization paths remain protected until their replacement passes acceptance gates. Stable role IDs and business catalogs remain managed by IAM; editable display names are not schema relation names. No access JWT permission graph or token database is introduced. Document retains workspace/resource ownership and enforcement; SpiceDB grants do not replace current session/account eligibility or private-content guards.

A dedicated Angular developer ACL login portal must use the existing independently provisioned eligibility, fresh authentication, current password and single-use factor proof requirements for every control-plane read/mutation. Organization administrators receive separate scoped business UI and cannot redefine platform policy or acquire developer eligibility. Raw SpiceDB operations and credentials remain internal. Existing organization isolation, upstream deny precedence, same-authority matching and employee-private content boundaries remain mandatory throughout migration.

Spring method security remains the enforcement entry point. Migrated evaluators use SpiceDB for bounded relationship-authority checks while preserving registered operation requirements, identical authority witnesses across applicable layers, coherent graph/policy revisions and fresh IAM/domain guards; sections 4.1–4.5 of the requirements change define the integration. Existing transaction-bound evaluators must be refactored into short context/revalidation transactions around an external SpiceDB call, never hold SQL transactions during that network call, and preserve an explicit cross-service authorization race contract.

The first Phase-3 Auth canary is restricted to `organization.group.create` in an explicit server-configured organization cohort and is disabled by default. It is a temporary stricter intersection: a short IAM transaction establishes current identity, policy and projection fences; SpiceDB checks the same authority UUID at the category and scoped layers at one pinned fully-consistent graph revision outside SQL; the existing IAM authorization and all fences are revalidated under the final group-creation transaction. Any dependency or revision uncertainty fails closed. The legacy decision remains required for every canary success, so disabling the canary returns to a continuously exercised legacy path. Organization schema v2 separates category and scoped grantees, and V41 requires regeneration of prior organization projections before the canary is enabled. This is a limited local canary contract, not a complete organization IAM cutover.

Phase-5 preparation adds separately disabled management canary checks and V45 reprojection for group-scoped responsibility tuples, which now require current group membership. The twelve registered Auth organization-management operation keys are selected by the management switch; focused tests cover registry selection and representative fail-closed mutation paths. The management switch remains off until entry-path acceptance is complete, SQL authority matching is replaced by a verified graph decision, and the observation and rollback gates in the SpiceDB requirements change pass. No legacy cache key family is retired by the preparatory code.

Assignment canary preflight additionally binds its recipient to one organization or ancestor department management scope at the operation's pinned SpiceDB revision. The final SQL transaction rechecks the recipient's active organization membership, target ancestry and department scope types. The existing SQL recipient guard remains an additional constraint pending graph equivalence, race and live rollback acceptance. This does not complete Phase 5 or change the default-disabled flags.

The local test cohort accepted one graph-authoritative assignment and revocation of an existing synthetic employee group membership, then demonstrated legacy owner allow and revoked-admin deny with all SpiceDB flags disabled. Projection reached revision 25/25 and source version 9/9 after revocation. This is a narrow rollback observation; responsibility, restriction, employee lifecycle and other operation families still need release-gate evidence.

On 19 October 2026 the same local cohort exercised additional graph-authoritative management writes for responsibility grants/revocations, organization/department/team restrictions, scoped group membership, group rules, synthetic employee creation and credential reset, and reversible employee removal/restoration. Account-specific deny is checked for the exact scope and operation at the pinned SpiceDB revision; an unrelated restricted operation must not deny management access. The final projection reached required/applied revision 71/71 and source version 35/35. After disabling all five test canary/projection switches, observed owner allow and ordinary/revoked-employee deny results matched the graph-enforced results. This is local final-state rollback evidence, not a release cutover: concurrent mutation, projection replay/order, direct-service paths, internal collaboration authorization and full-suite gates remain open.

The organization projection tuple ledger is a durable superset of relationships that a worker may have touched until a complete pass is acknowledged. Before remote writes, the worker records the fresh desired tuples alongside the previous ledger under its lease. A failed or source-superseded pass leaves that superset for retry, so the next pass deletes tuples absent from the latest MySQL snapshot. Only a fully acknowledged pass replaces the ledger with its exact desired set and advances the applied revision and ZedToken. This closes the stale-tuple gap caused by partial remote writes or source changes during projection; it does not change the requirement for a current required/applied authorization fence.

An additional default-disabled management enforcement switch now selects the graph's pinned same-authority result as the operation-authority witness for that explicit cohort. Current IAM session, account, organization membership, policy versions, projection fence, and recipient managed-scope guards remain mandatory. The assignment-recipient guard still matches SQL scope and authority until an equivalent graph proof binds the administrator's authority to that same managed scope. The local read-only enforcement and outage probes passed, but revocation races and the remaining management mutation paths remain release gates. Keep both management and enforcement switches disabled outside controlled validation until those gates pass.

One controlled graph-authoritative group creation has since passed: its projection reached required/applied 21/21, and legacy rollback read the created group while denying the revoked employee. This evidence covers group creation only. Graph-enforced management reads allowed the OWNER and denied the revoked employee across the scoped admin and group list/detail routes. The current policy-candidate cache is restricted to individual document operations; organization-entitlement snapshots still serve navigation and unmigrated authorization, so neither key family is eligible for blanket deletion in this phase.

Credential enrollment/recovery target: sections 9.1–9.7 of the requirements change define a built-in developer operator separate from platform users. At provisioning/startup, a concurrency-safe SQL existence check inserts the stable default operator once if absent, initially `unidocadmin/admin` with mandatory password replacement. Preserve changed credentials/usernames and disabled/deleted tombstones on subsequent starts. Protect first enrollment through an installation-owned activation proof/channel so the known default password cannot let a remote visitor claim the platform. The developer has its own principal/session/API realm, no PERSONAL account, AccountGroup, membership, workspace or content grant, and can create initial business roles without depending on one. This supersedes older no-default-identity and verified-PERSONAL-account developer requirements; preserve audit history while migrating the existing gate/storage.

Developer login/change/recovery uses an entirely dedicated API group excluded from ordinary product navigation/API listings, with real server-side realm/audience and proof enforcement. Personal users, students, education institution administrators and organization administrators use the same username-plus-verified-email/link/set-password flow through distinct category-specific API groups; administrator recovery preserves existing eligibility and never appoints/promotes a user. Employees retain administrator-authorized emailed setup/reset links. Developer recovery requires independent proof in addition to email; fixed name/project questions are not recovery credentials. Expiring, purpose-bound hashed tokens replace legacy OTP/admin-visible PIN flows only after compatible implementation gates. The developer flow is implemented for the explicit Phase-4 test configuration; product-category and employee credential replacements remain later credential slices.

Phase-4 implementation uses distinct `iam_developer_operator` principal, session, factor, setup/recovery-proof, recovery-code, security-notice and audit storage. The installation-owned activation proof resides in ignored Auth `.secrets/developer-activation`, is hashed before MySQL storage, and is consumed when first-use enrollment completes. Operator password recovery requires an emailed token and an independent offline code; password change and recovery revoke operator sessions and replace factor sets. The operator chain and bootstrap are enabled for `auth-service-test` UAT. Other environments retain a disabled default and require an explicit `AUTH_DEVELOPER_OPERATOR_ENABLED` setting plus an HTTPS recovery origin and ingress controls before rollout. When operator mode is enabled, developer catalog and the professional/student-staff reconciliation commands use the operator proof realm and explicit operator audit attribution; product-linked developer admission cannot be an alternate path. The legacy product-linked path remains available only while operator mode is off for staged migration and rollback.

## Current role, workspace and lifecycle contract — 13 October 2026

This section is the authoritative specification agreed with the platform owner. It supersedes conflicting older role, group-entry, student-enrollment, workspace-access, quota and content-deletion rules below. Older implementation-decision sections describe existing behavior to migrate, not competing requirements. This amendment specifies the target; it does not claim the target is already implemented. Technology, identity/session security, cross-service boundaries, secret protection, transactional outbox and fresh authorization requirements remain in force.

### Dynamic roles and policy precedence

The platform owner/developer manages application role definitions, role-authority bindings, method-operation policies and stakeholder-role mappings through a protected role manager. Ordinary users, organization administrators and student administrators cannot redefine application roles or platform policy. Local administrators can exercise developer-enabled management powers within their own scope, including applying eligible predefined local responsibilities. Product users interact with invitations, sharing, members and approvals, not the role-management model.

The three stakeholder contexts are individual/basic, organization/professional and student/institutional. These are workspace/account contexts, not one global role attached to a human and not three immutable role enums. Resolve the context from the selected, currently unlocked account and its verified workspace/membership relationships. Linked accounts never union their privileges. Role definitions and capability assignments are data-driven; existing hardcoded role checks must migrate to this model without becoming a second authorization path.

Removing an existing capability, such as file sharing, from the individual category role must affect subsequent fresh protected operations without coding, redeployment, relogin or waiting for Kafka. Other category roles and unrelated capabilities are unchanged. Defining a new business operation still requires implementing and registering that operation. Disabling new sharing does not silently delete previously shared content or revoke recipients; those require explicit mutations.

Permission is constrained by all applicable upstream policies. The developer's platform/category capability bounds organization policy; organization policy bounds department policy; department policy bounds team/group policy. A downstream grant never overrides an upstream deny. Evaluate applicable parents based on the verified resource and actor scope, not merely the highest role name. A missing local grant is not automatically an explicit deny, but no applicable grant means denial. Unrelated branches cannot grant access to each other. Resource ownership does not override a disabled capability, membership restrictions, revocation or required step-up.

Where a method policy requires authority matching at both category and local scope, the same required authority must be present at both layers. ALL_OF requires every required authority in their intersection; ANY_OF requires at least one common required authority. Matching different alternatives independently at the two layers cannot authorize. An applicable explicit operation/resource deny defeats all alternatives.

The developer control plane has separately provisioned, audited eligibility, fresh authentication and step-up. Organization OWNER/ADMIN names, account linking and editable policy entries cannot confer it. No public setup endpoint, secret bypass or unrestricted bootstrap identity. This control-plane identity is not an automatic grant to read employee private content.

IAM owns role/capability definitions, stakeholder bindings, IAM memberships, upstream policy restrictions and current enforcement evidence. Document owns resource metadata, visibility/sharing records, private-space boundaries, publication state, storage accounting and content deletion. Document combines fresh IAM authority with its own resource guards. No service reads another service's database. This dynamic-role change does not transfer WorkspaceMember or all file ACL storage into IAM.

### Individual/basic workspace

- Individuals manage their own personal files/folders and may share eligible content by invitation with view or read/write access, when their current role enables those operations.
- Only the file owner may delete an individual file. A collaborator's write permission does not imply deletion. Collaboration invitation is necessary to edit another owner's content.
- Individuals may create personal P2P collaboration groups, invite other individual accounts, remove members from groups they own and leave another owner's group. Group ownership does not confer ownership of every member's file.
- Groups and content are invitation-only. This basic workspace exposes no organization discovery, organization membership or cross-context collaboration. A human may separately hold another account, but an organization account cannot participate as a basic P2P member.
- Personal groups are not organization Groups with a fabricated organization ID. Use one group capability with explicit workspace context and context-specific admission rules.
- Deleting a collaboration group follows the global deletion window and is an explicit container-deletion exception to owner-only individual file deletion.

### Organization/professional workspace

Each organization is isolated: no cross-organization discovery, invitations, communication or external/basic/student collaboration. Employees do not self-join; Organization Admin provisions employee accounts.

| Local responsibility | Permitted scope when platform capabilities allow it | Mandatory boundary |
| --- | --- | --- |
| Organization Admin | Provision employees; assign employees to departments/groups; configure their scoped view/create/edit/delete access; manage public-space publication approval | Cannot redefine application roles, edit another author's public content, inspect employee private spaces, or override developer policy |
| Department Admin | Assign employees of that department to one or more groups and control downstream content-consumption permissions within the department | Cannot override organization restrictions or operate outside the department |
| Group/Team Admin | Configure group-member content capabilities and invite existing organization members to collaborate | Cannot assign employee membership, override department/organization restrictions or invite outside the organization |
| Employee | Use assigned department/group content and manage their private employee space | Cannot exceed assigned access or alter upstream policy |

Collaboration invitations do not create employee, department or team membership; those are distinct authorized assignments. A team invitation cannot bypass an upstream block on the recipient or resource.

Professional resources select one verified owning group ancestry, bounded to 32 levels; unrelated actor memberships do not contribute grants. An accepted exact-resource invitation may admit another current employee of that organization without assigning team membership, while every restriction on the resource's owning ancestry still applies. The service-authenticated IAM request's `exactResourceAccess` hint is limited to registered file/folder read, download, copy and collaborative edit checks; Document must independently verify the actual relationship and enforce its preset. Returned authority witnesses must remain common across category, IAM scope and Document resource layers. Legacy personal organization anchors migrate through an explicit, audited developer reconciliation to a separate organization account; the personal account and its basic content are preserved, and existing target revocations are not revived.

Organization public space is readable by employees. Employees may create content and submit it for Organization Admin publication approval. Only Organization Admin may delete public-space content. Even Organization Admin may edit only their own content, not another author's. The private draft and published lifecycle must not expose unapproved content as public.

Each employee also has a private space inside the organization. The employee may create/view/edit/delete their content and share with other employee private spaces within the same organization, when enabled. Organization administrative rank gives no visibility into that space. Resource privacy still applies even when the organization pays for storage. An employee-private sharing recipient receives only the explicitly granted resource access.

### Student/institutional workspace

Student workspaces are isolated from external workspaces and other institutions. Student verification during self-registration is sufficient for institutional admission: verify institutional email where available, otherwise manually review student ID/admission evidence. Admission and course joining are separate; after verification, students may self-join any currently offered course. Earlier trusted-administrator course-assignment requirements are obsolete for this model.

| Responsibility | Permitted actions when platform capabilities allow them | Prohibited powers |
| --- | --- | --- |
| Student Admin, appointed by developer | Update/remove course catalog entries where lifecycle permits; invoke semester creation, which automatically creates the semester workspace; review admission documents; review student reports and submit evidence to platform authority | Cannot remove finalized/ongoing-semester courses, manage students, set student roles, assign students to courses, define policy or directly expel students |
| Normal Student | Self-join offered courses; create/share own content; edit/delete own content; edit another's content only by collaboration invitation; create private study groups within a course workspace | Cannot remove courses, remove other course members, delete another owner's individual content or override platform policy |

A study-group owner can view/create content, invite collaborators and schedule group deletion. Ownership alone cannot edit another's content. Uninvited students cannot discover the study group. Group deletion is subject to notice and the container-purge exception below.

Students may report suspected intruders or policy violations. Student Admin reviews and submits supporting evidence; platform authority makes the enforcement decision. A proven intruder may be removed. A legitimate policy-violating student retains their own space/content management and public-content viewing but loses collaboration. A legitimate student can be removed only when the institution terminates their studentship; record verified termination evidence. Reporting or Student Admin recommendation alone does not revoke membership. Apply restriction/revocation transactionally with fresh authorization, versions, audit, outbox and durable notice. Existing student organization roles must not supply alternate organization-admin or enrollment-curator powers.

### Content quota ownership

Personal content, including content contributed/shared into personal groups, courses and study groups, consumes its owner's individual quota. Sharing does not move the charge to recipients and does not duplicate the charge merely because a file appears in multiple views. A retained independent copy consumes the copying account's quota. Physical deduplication must not bypass logical quota accounting.

Institution course-space capacity is the sum of participating institutional students' individual quota allocations; shared course content still consumes each contributing owner's quota. This is a pooled capacity view, not an extra quota allocation multiplied by the number of courses. Use a single institution pool across its course spaces; document contributor eligibility and changes to the pool without silently purging existing content on a quota decrease.

Organization storage, including employee-private content inside that professional workspace, consumes the separate organization allocation. Keep this billing/usage ownership independent of an administrator's right to read content.

### Global deletion and organization override

All content/container deletions use a one-week notice/recovery window by default in individual and student workspaces. During the window, affected members may copy content they are still authorized to read into their own space, subject to destination quota. At the deadline the deleted item/container and all remaining content are hard-purged. Independent copies retained outside the deleted container survive. Container deletion may purge another member's remaining contributed content after notice; it does not authorize immediate owner-only file deletion by a collaborator.

Organizations control deletion timing for their paid professional workspace and may choose immediate purge or any longer retention. This is an explicit platform-authorized exception to the global default, not a downstream override of an unrelated upstream deny. Only an authorized organization policy editor may change that setting; other organization access/privacy restrictions still apply. Capture the applicable deletion deadline when scheduling; changing organization policy does not silently accelerate already-notified pending deletions.

Persist deletion intent, purge deadline, affected-recipient notices and outbox records transactionally. Purge content metadata, binaries, versions and projections through retry-safe owning-service workflows; an IAM event alone cannot erase Document/S3 data. Retained bytes count until actual purge releases them. Serialize copy/restore/deletion eligibility so incomplete copying or stale cache state cannot resurrect purged content. Provide durable notices without exposing private contents to unauthorized administrators.

The implementation plan is maintained in `docs/METHOD_LEVEL_SECURITY_IMPLEMENTATION_PLAN.md`. Implement complete vertical slices, preserve already-running security until each replacement passes its checks, and update the recorded implementation status as slices ship.

### Individual method-security implementation decisions — 14–15 October 2026

IAM serializes editable policy changes through one transactional global revision fence. A protected operation establishes the current SQL revision and current selected-account/session eligibility; cached immutable policy candidates never constitute reusable authorization. A catalog write commits its version, audit and outbox in the same transaction. This initially applies to registered individual operations; existing organization/student enforcement remains in place until its own phase is migrated.

The developer console uses a separate login flow from the product workspace. Its eligibility is provisioned against an existing verified personal account by an audited local infrastructure operation. Every control-plane read or mutation requires fresh normal login authentication, the current password and a separately issued single-use factor; only hashes of factors are stored. Editable roles cannot create developer eligibility. No default unrestricted account is created.

Personal-group deletion first records PREPARING, without starting a deadline. Document persists its affected-recipient notices, then acknowledges a durable batch through the service-authenticated IAM API outside its database transaction. IAM captures the one-week deadline only after that acknowledgement. The same receipt cannot extend it. Cancellation is owner-only before the deadline and does not restore revoked invitations or memberships. Document obtains current IAM closure state before purging; an outage retains content and charged bytes. Group owners must resolve active group ownership or complete a captured closure before unlinking or permanently removing their personal account; nonowner departure revokes current participation transactionally.

Two-second notice windows are restricted to an explicit test profile and isolated test database. Production defaults and previously captured deadlines remain unchanged. A test window is not a developer permission bypass.

Selected-account evidence includes the current account type from IAM, rather than inferring basic context from an owner workspace alone. Only verified PERSONAL context enters the individual dynamic enforcement path; existing professional/student private-space checks remain in force until their own migration phases. Group member and pending invitation listings are bounded and scoped to current membership and ownership respectively; they do not create account discovery.

Document persists COPY provenance atomically with the target upload intent and quota reservation. Ordinary upload creation/commit cannot redeem a COPY intent. The dedicated copy finalizer establishes fresh source eligibility and checks the captured source generation and deadline before publication; cleanup retains the COPY fence. Source identifiers in this provenance do not introduce foreign keys that prevent source purge or erase independent retained copies.

## 1. Purpose

Build a production-oriented Drive-like platform using Java/Spring Boot microservices.

The differentiating feature is contextual and inherited access. Users can have independent Personal, Company, University, or other accounts that are soft-linked into one unified drive experience. Organization and group membership can automatically grant access to workspaces and their directory/document trees.

This document is the architectural source of truth for implementation. If implementation requirements conflict with this document, identify the conflict before changing domain semantics.

---

## 2. Technology Baseline

- Java 25
- Spring Boot 4.1.1
- Maven 3.9.16
- Spring Security
- Spring Data JPA
- MySQL
- Flyway
- Redis
- Caffeine
- Apache Kafka
- Elasticsearch
- S3-compatible object storage
- Testcontainers
- Prometheus
- OpenTelemetry
- Centralized structured logging
- Angular frontend
- API Gateway / Load Balancer

### Auth standalone diagnostic profile

The user-authorized `offline` profile starts without any external service,
including MySQL, and without credentials or signing keys. It loads a separate
minimal web configuration, excluding domain services and persistence/integration
auto-configuration. It exposes process health/readiness and Swagger for the reduced
offline surface. Auth APIs, JWKS and internal authorization return 503 with
no-store responses. It creates no identities, sessions or temporary transactional
state and does not grant permissions or issue tokens. Offline readiness indicates
process availability, not readiness to serve authentication traffic. `offline`
takes precedence when combined with `dev`; Compose dependency ordering is unchanged.
The normal `dev` profile retains existing capabilities, dependency requirements
and security protection, with Swagger enabled. Other profiles retain opt-in API
documentation. MySQL remains the transactional source of truth in operational modes.

### System-of-record rules

- MySQL is the durable source of truth for transactional domain state.
- S3 is the durable source of truth for document binary content.
- Redis and Caffeine are disposable caches/projections.
- Elasticsearch is a reconstructible search projection, never the source of truth.
- Kafka transports asynchronous domain/security events.
- Use the transactional outbox pattern for DB-to-Kafka propagation.
- Kafka consumers must be idempotent.
- Services must never access another service's database directly.

---

## 3. Service Boundaries

### IAM / Auth Service

Owns:

- PendingRegistration
- RegistrationVerification
- User
- UserProfile
- UserContact
- UserPreference
- UserAccount
- LoginIdentity
- AccountCredential
- AccountGroup
- AccountGroupMember
- UserSession
- SessionAccountGrant
- SessionGrantPolicy
- SecurityAuditEvent
- Organization
- OrganizationAuthPolicy
- OrganizationMembership
- Group
- GroupMembership
- GroupJoinRequest
- IAM authorization projection/cache
- IAM outbox events

### Document Service

Owns:

- Workspace
- WorkspaceMember
- WorkspaceJoinRequest
- Directory
- Document
- DocumentVersion
- DocumentFavorite
- Resource AccessPolicy / StepUpGrant when resource-specific
- Document-domain outbox events

### Notification Service

Owns:

- Notification
- Notification delivery state
- Notification outbox events as needed

Cross-service identifiers such as `accountId`, `organizationId`, or `createdBy` are UUID values. Do not create database foreign keys across service databases.

---

## 4. Identity Model

### 4.1 User

`User` represents the human/person and global profile.

Suggested fields:

```text
User
- UUID id
- String displayName
- UserStatus status
- Instant lastLoginAt
- Instant createdAt
- Instant updatedAt
```

`User` must not be used as an authorization shortcut. Authorization occurs through a `UserAccount` and current memberships/session grants.

### 4.2 UserProfile

```text
UserProfile
- UUID userId
- String firstName
- String middleName
- String lastName
- LocalDate dateOfBirth (optional; only collect if required)
- String profileImageKey
- String locale
- String timeZone
- Instant updatedAt
```

### 4.3 UserContact

Supports multiple contact methods.

```text
UserContact
- UUID id
- UUID userId
- ContactType type
- String value
- boolean primary
- boolean verified
- Instant verifiedAt
- Instant createdAt
```

### 4.4 UserPreference

```text
UserPreference
- UUID userId
- UUID preferredAccountId
- Theme theme
- String locale
- String timeZone
- boolean emailNotifications
- boolean pushNotifications
- boolean securityNotifications
- Instant updatedAt
```

`preferredAccountId` is a navigation/default preference only. It must never bypass authentication.

---

## 5. Pending Registration

Incomplete registration must not create a real authorized User/UserAccount.

### PendingRegistration

```text
PendingRegistration
- UUID id
- RegistrationType registrationType
- String firstName
- String middleName
- String lastName
- String displayName
- String identifier
- IdentityType identityType
- String passwordHash
- RegistrationStatus status
- UUID organizationId (nullable when applicable)
- UUID invitationId (nullable when applicable)
- Instant createdAt
- Instant expiresAt
- Instant verifiedAt
- Instant completedAt
```

Statuses:

```text
PENDING_VERIFICATION
VERIFIED
COMPLETED
EXPIRED
CANCELLED
```

### RegistrationVerification

```text
RegistrationVerification
- UUID id
- UUID pendingRegistrationId
- VerificationType verificationType
- String destination
- String codeHash
- String tokenHash
- VerificationStatus status
- int attemptCount
- Instant createdAt
- Instant expiresAt
- Instant verifiedAt
```

Statuses:

```text
PENDING
VERIFIED
EXPIRED
FAILED
REVOKED
```

Never store OTPs, verification tokens, PINs, or passwords in plaintext.

### Registration lifecycle

```text
Registration request
    ->
PendingRegistration(PENDING_VERIFICATION)
    ->
RegistrationVerification
    ->
VERIFIED
    ->
transactional provisioning
    ->
User / Profile / Contact
UserAccount / LoginIdentity
AccountGroup / AccountGroupMember
    ->
PendingRegistration(COMPLETED)
```

`VERIFIED` is intentionally distinct from `COMPLETED`, so provisioning can be retried without requiring identity verification again.

A pending registration cannot own documents, join normal groups, create normal authenticated sessions, or receive organization/workspace permissions.

---

## 6. UserAccount and Unified Drive

`UserAccount` is an independently authenticated account/security context.

Examples:

```text
User: John Smith

AccountGroup
â”œâ”€â”€ Personal UserAccount
â”œâ”€â”€ Acme UserAccount
â””â”€â”€ University UserAccount
```

These are real independent accounts, not folders.

### UserAccount

```text
UserAccount
- UUID id
- UUID userId
- AccountType type
- String displayName
- AccountStatus status
- Instant createdAt
- Instant updatedAt
```

For pre-provisioned organization identities, do not force a `User` association until control/linking has been verified if the human identity is not yet known.

### LoginIdentity

Represents an identifier/login mechanism.

```text
LoginIdentity
- UUID id
- UUID accountId
- IdentityType type
- String identifier
- String passwordHash
- String externalSubject
- IdentityStatus status
- long credentialVersion
- Instant lastAuthenticatedAt
- Instant createdAt
- Instant updatedAt
```

### AccountCredential

Additional account-root unlock mechanisms.

```text
AccountCredential
- UUID id
- UUID accountId
- CredentialType type
- String credentialHash
- CredentialStatus status
- long version
- Instant createdAt
- Instant updatedAt
```

Potential credential types:

```text
PASSWORD
PIN
PASSKEY
TOTP
SSO
```

### AccountGroup

Soft-links independent accounts into the unified drive experience.

```text
AccountGroup
- UUID id
- UUID userId
- AccountGroupStatus status
- Instant createdAt
- Instant updatedAt
```

Do not use AccountGroup to grant organization permissions.

### AccountGroupMember

```text
AccountGroupMember
- UUID accountGroupId
- UUID accountId
- LinkStatus status
- LinkMethod linkMethod
- UUID linkedByAccountId
- Instant linkedAt
- Instant disconnectedAt
```

A UserAccount may belong to at most one AccountGroup.

Account linking requires proof/control and audit history. Linking accounts must never itself grant organization permissions.

---

## 7. Authentication and Sessions

### Core principle

JWT proves authenticated identity/session context. It must not contain the complete mutable permission graph.

Suggested access token claims:

```text
sub
sid
iss
aud
iat
exp
```

Use asymmetric signing and `kid`-based JWKS key rotation.

Every service validates JWTs locally:

- signature
- issuer
- audience
- expiration
- permitted algorithm
- required claims

Use HTTP 401 for missing/invalid/expired authentication and 403 for an authenticated principal lacking permission.

### UserSession

One login creates an umbrella session:

```text
UserSession
- UUID id
- UUID accountGroupId
- UUID loginAccountId
- SessionStatus status
- Instant authenticatedAt
- Instant lastActivityAt
- Instant expiresAt
- Instant revokedAt
```

### SessionAccountGrant

Represents an account currently unlocked within a session.

```text
SessionAccountGrant
- UUID id
- UUID sessionId
- UUID accountId
- GrantStatus status
- AuthenticationMethod authMethod
- long credentialVersion
- Instant authenticatedAt
- Instant lastActivityAt
- Instant idleExpiresAt
- Instant absoluteExpiresAt
- Instant revokedAt
- GrantRevocationReason revocationReason
```

The account whose credentials created the session is automatically granted:

```text
authMethod = LOGIN
```

It must not immediately require another PIN/password challenge.

Other linked accounts start locked and require a challenge.

Example:

```text
Login using University credentials

SESSION
â”œâ”€â”€ Personal    LOCKED
â”œâ”€â”€ Acme        LOCKED
â””â”€â”€ University  UNLOCKED (LOGIN)
```

After Acme PIN verification:

```text
SESSION
â”œâ”€â”€ Personal    LOCKED
â”œâ”€â”€ Acme        UNLOCKED (PIN)
â””â”€â”€ University  UNLOCKED (LOGIN)
```

Multiple account grants may remain active simultaneously. Do not model a single server-side global `activeAccountId`.

The requested resource/account root determines context.

### Grant validity

A grant is valid only when all relevant conditions remain valid:

```text
account is linked/available
AND SessionAccountGrant is ACTIVE and unexpired
AND underlying OrganizationMembership is ACTIVE when applicable
AND required Group/Workspace authorization is valid
AND optional StepUpGrant is valid when required
```

Expiration can be enforced lazily at authorization time. A cleanup worker may later mark/delete expired grants.

### SessionGrantPolicy

```text
SessionGrantPolicy
- UUID id
- PolicyScopeType scopeType
- UUID scopeId
- Duration idleTimeout
- Duration absoluteTimeout
- boolean allowMultiAccount
- boolean requireReauthentication
- long version
- Instant createdAt
- Instant updatedAt
```

Organization security policy may override user preference.

Possible grant revocation reasons:

```text
LOGOUT
IDLE_TIMEOUT
ABSOLUTE_TIMEOUT
MEMBERSHIP_REVOKED
ACCOUNT_DISABLED
CREDENTIAL_CHANGED
ADMIN_REVOKED
SECURITY_POLICY_CHANGED
SESSION_REVOKED
```

---

## 8. Preferred Account and Fallback

Preferred account is stored in `UserPreference.preferredAccountId`.

It affects navigation/default selection only.

It must never automatically unlock an account.

Fallback after account/organization revocation:

1. Use Personal if Personal remains available.
2. If Personal is unavailable and exactly one account remains, use that account.
3. If multiple non-personal accounts remain, show an account selector unless a future explicit ordering rule is defined.
4. If the fallback account lacks a valid SessionAccountGrant, require its authentication challenge before exposing data.

Revoking the account originally used for login does not necessarily terminate the entire AccountGroup session if another valid account remains usable. If no usable account remains, terminate the session.

---

## 9. Organizations

### Organization

```text
Organization
- UUID id
- String name
- String slug
- OrganizationType type
- OrganizationStatus status
- Instant createdAt
- Instant updatedAt
```

### OrganizationAuthPolicy

```text
OrganizationAuthPolicy
- UUID id
- UUID organizationId
- AuthMethod authMethod
- String emailDomain
- boolean enabled
- boolean allowPinUnlock
- boolean requireMfa
- Instant createdAt
- Instant updatedAt
```

### OrganizationMembership

```text
OrganizationMembership
- UUID id
- UUID organizationId
- UUID accountId
- OrganizationRole role
- MembershipStatus status
- String officialEmail
- String memberCode
- String externalIdentity
- long version
- Instant joinedAt
- Instant revokedAt
- UUID revokedBy
- Instant createdAt
- Instant updatedAt
```

Use generic `memberCode` rather than employee-specific naming.

Active organization membership is the top-level authorization kill switch for organization descendants.

Organization-specific fields such as department, student ID, employee/member code, official organization email, or organization role do not belong on `User`.

### Organization revocation

Revocation must:

```text
OrganizationMembership ACTIVE -> REVOKED
    ->
increment authorization version
    ->
write OutboxEvent in same transaction
    ->
invalidate/update IAM Redis projection
    ->
publish Kafka security event
    ->
downstream services invalidate Caffeine
    ->
revoke relevant SessionAccountGrant(s)
    ->
create durable notification
    ->
calculate safe fallback
```

After revocation, organization content must not leak through:

- root/account listing
- search
- recent items
- favorites
- suggestions
- notifications containing protected content
- autocomplete

Audit history may retain internal references.

---

## 10. Groups and Contextual Access

### Group

```text
Group
- UUID id
- UUID organizationId
- UUID parentGroupId
- String name
- GroupType type
- GroupStatus status
- Instant createdAt
- Instant updatedAt
```

Suggested group types:

```text
DEPARTMENT
COURSE
CLASS
TEAM
PROJECT
CUSTOM
```

### GroupMembership

```text
GroupMembership
- UUID id
- UUID groupId
- UUID accountId
- String role
- GroupMembershipType membershipType
- MembershipSource source
- String sourceReference
- MembershipStatus status
- Instant validFrom
- Instant validUntil
- long version
- Instant createdAt
- Instant updatedAt
```

Customizable roles should generally be data/string/table-driven rather than hard-coded enums.

Membership sources may include:

```text
ORGANIZATION_ASSIGNMENT
ADMIN_APPROVAL
COURSE_ENROLLMENT
INVITATION
DIRECTORY_SYNC
```

Do not allow a user to self-claim sensitive department/course access. A group administrator may explicitly enable open joining for ordinary groups. University COURSE groups use trusted university/organization-administrator enrollment, never student-supplied enrollment claims or group approval.

Group discovery and joining are separate rules. Discovery scopes are ORGANIZATION, DEPARTMENT (an explicit active department membership), and INVITATION_ONLY. Joining modes are OPEN, APPROVAL, INVITATION_ONLY, and COURSE_ENROLLMENT. Only APPROVAL groups accept join requests. Department groups cannot enable OPEN joining; department authority still requires trusted assignment or approval. Discovery alone grants no membership, workspace permission, or session account unlock.

University COURSE groups represent a single academic semester offering. Trusted enrollment atomically replaces a student's current semester course list and automatically grants the confirmed course memberships. Previous course groups and their descendants become invisible immediately and course membership ends at the semester deadline. A new semester uses new course group IDs; an offering's semester cannot be rebound to expose earlier content. Students cannot confirm their own enrollment. Organization OWNER/ADMIN accounts ingest trusted university data; no external university connector is assumed.

Group administrators are designated by an explicit canManageGroup flag assigned by organization OWNER/ADMIN. Custom role names do not confer this authority. This designation is scoped to the effective group membership, current organization authority, account grant and time window; revocation immediately disables it.

### GroupJoinRequest

```text
GroupJoinRequest
- UUID id
- UUID groupId
- UUID accountId
- String requestedRole
- RequestStatus status
- String reason
- UUID reviewedBy
- Instant reviewedAt
- Instant createdAt
```

---

## 11. Workspace Authorization

### Workspace

```text
Workspace
- UUID id
- WorkspaceOwnerType ownerType
- UUID ownerId
- UUID organizationId
- UUID groupId
- String name
- String description
- WorkspaceAccessScope accessScope
- WorkspaceStatus status
- UUID createdBy
- Instant createdAt
- Instant updatedAt
```

Access scopes:

```text
OWNER
ORGANIZATION
GROUP
RESTRICTED
```

Semantics:

- OWNER: personal owner only.
- ORGANIZATION: any active member of the owning organization.
- GROUP: active organization member plus active owning-group membership.
- RESTRICTED: active organization member plus explicit WorkspaceMember.

Everything is private to the platform. The UI may call RESTRICTED a "Private Workspace."

### WorkspaceMember

```text
WorkspaceMember
- UUID id
- UUID workspaceId
- UUID accountId
- WorkspaceRole role
- MembershipStatus status
- UUID addedBy
- Instant createdAt
- Instant revokedAt
```

### WorkspaceJoinRequest

```text
WorkspaceJoinRequest
- UUID id
- UUID workspaceId
- UUID accountId
- RequestStatus status
- String message
- UUID reviewedBy
- Instant reviewedAt
- Instant createdAt
```

Group membership grants inherited access to GROUP workspaces.

Workspace membership grants explicit access to RESTRICTED workspaces.

Do not create per-user per-file ACL rows for inherited workspace access.

---

## 12. Directory Hierarchy

Use one self-referencing `Directory` entity. Do not create separate SubDirectory classes/tables.

```text
Directory
- UUID id
- UUID workspaceId
- UUID parentDirectoryId
- String name
- DirectoryType type
- DirectoryStatus status
- long directDirectoryCount
- long directDocumentCount
- long descendantDirectoryCount
- long descendantDocumentCount
- long descendantSizeBytes
- UUID createdBy
- Instant createdAt
- Instant updatedAt
```

Directory types:

```text
ROOT
NORMAL
```

Prefer one root per workspace. A virtual/lazy root is acceptable for empty accounts/workspaces if useful at scale.

Hierarchy:

```text
ROOT
â”œâ”€â”€ Engineering
â”‚   â”œâ”€â”€ Backend
â”‚   â”‚   â””â”€â”€ API
â”‚   â””â”€â”€ Frontend
â””â”€â”€ Finance
```

A subdirectory is simply a Directory whose `parentDirectoryId` points to another Directory.

Prevent cycles when moving directories. A directory cannot be moved under itself or any descendant.

### Document service planning baseline

The [Document service implementation plan](document-service-plan/IMPLEMENTATION_PLAN.md)
records planned slices, infrastructure, IAM API contracts and acceptance gates;
these decisions do not assert that Document is deployed.

- Root depth is0; allow at most10 nested folder levels below it. Files may reside
  in depth10 folders. Create, whole-subtree move and restore must enforce the limit
  and cycle prevention under concurrency. Root cannot move or enter item trash.
- RustFS is the selected S3-compatible binary store for Document, in a private
  Document-owned bucket with separate scoped credentials. MySQL owns metadata and
  application-managed immutable version history. Restoring an old version creates
  a new current version rather than overwriting history.
- Soft-deleted items are restorable before `deletedAt + Duration.ofDays(30)` in
  UTC. Trash hides entire directory subtrees immediately through ancestor checks;
  independently pre-trashed children retain their own deletion state on restore.
  Leased, fenced, bounded jobs purge objects after eligibility. Actual storage
  cleanup may lag; bucket object-age lifecycle is not the trash recovery policy.
- Direct counters are transactional counts of locally ACTIVE children, exposed
  only for effectively ACTIVE directories. Ancestor statistics exclude hidden
  subtrees. `descendantSizeBytes` counts current live versions; quota accounting
  separately includes retained history, trash and staged/deletion-pending bytes.
- Initial downloads use an authenticated Document streaming gateway. A reusable
  presigned RustFS GET is not a revocable IAM permission lease; direct downloads
  require a separately approved bounded-exposure policy before introduction.
- OWNER workspaces initially retain selected-account isolation with verified
  account/user owner evidence; shared scopes and local roles follow existing
  workspace semantics. Anonymous/public links remain outside the private platform.

### Directory counters

`directDirectoryCount`:
number of immediate child directories.

`directDocumentCount`:
number of immediate documents.

`descendantDirectoryCount`:
all nested directories below this directory, excluding itself.

`descendantDocumentCount`:
all documents in the complete subtree.

`descendantSizeBytes`:
total binary size represented by documents in the subtree according to the chosen product semantics.

Direct counters should be updated transactionally with direct metadata changes.

Deep descendant counters may be maintained asynchronously through Outbox -> Kafka if needed to avoid hot-row contention. Eventual consistency is acceptable for UI statistics; it is not acceptable for authorization decisions.

Do not use Elasticsearch as the authoritative directory/file counter.

### Core indexes

Design directory lookups around workspace locality:

```text
(workspace_id, parent_directory_id, status, name, id)
```

Use cursor/keyset pagination rather than deep OFFSET pagination.

---

## 13. Document Model

### Document

```text
Document
- UUID id
- UUID workspaceId
- UUID directoryId
- UUID currentVersionId
- String name
- String mimeType
- long sizeBytes
- DocumentStatus status
- UUID createdBy
- Instant createdAt
- Instant updatedAt
```

### DocumentVersion

```text
DocumentVersion
- UUID id
- UUID workspaceId
- UUID documentId
- long versionNumber
- String storageKey
- long sizeBytes
- String checksum
- String mimeType
- UUID uploadedBy
- Instant createdAt
```

Carrying `workspaceId` into high-volume child metadata may be useful as a denormalized locality/routing key.

Document binary content belongs in S3, not MySQL.

Prefer direct-to-S3 presigned upload flows:

```text
Client -> metadata/upload authorization -> presigned S3 upload
       -> finalize metadata
       -> outbox/Kafka
       -> async processing/indexing
```

### DocumentFavorite

```text
DocumentFavorite
- UUID accountId
- UUID documentId
- Instant createdAt
```

A favorite never grants access. If authorization is revoked, a favorite must not make the document visible.

---

## 14. Resource Step-Up Authentication

Step-up verification is an additional factor, not a permission grant.

### AccessPolicy

```text
AccessPolicy
- UUID id
- ProtectedResourceType resourceType
- UUID resourceId
- VerificationType verificationType
- String credentialHash
- long credentialVersion
- Duration grantDuration
- boolean enabled
- Instant createdAt
- Instant updatedAt
```

### StepUpGrant

```text
StepUpGrant
- UUID id
- UUID sessionId
- UUID accountId
- ProtectedResourceType resourceType
- UUID resourceId
- VerificationType verificationType
- long credentialVersion
- Instant verifiedAt
- Instant expiresAt
- Instant revokedAt
```

Authorization semantics:

```text
not authorized + knows step-up code -> DENY
authorized + step-up required + no valid grant -> STEP_UP_REQUIRED
authorized + valid step-up grant -> ALLOW
```

Bind step-up grants to a UserSession/account so they cannot transfer across sessions.

---

## 15. Notifications

```text
Notification
- UUID id
- UUID accountGroupId
- UUID affectedAccountId
- UUID organizationId
- NotificationType type
- NotificationSeverity severity
- String title
- String message
- Instant createdAt
- Instant readAt
```

Organization revocation should generate a durable notification without unnecessarily exposing sensitive administrative details.

---

## 16. Security Audit

```text
SecurityAuditEvent
- UUID id
- UUID userId
- UUID accountId
- UUID sessionId
- UUID organizationId
- SecurityEventType eventType
- String ipAddress
- String userAgent
- Instant occurredAt
```

Events should include at least:

```text
LOGIN_SUCCESS
LOGIN_FAILURE
ACCOUNT_UNLOCKED
ACCOUNT_UNLOCK_FAILED
ACCOUNT_LINKED
ACCOUNT_UNLINKED
PIN_CHANGED
PASSWORD_CHANGED
SESSION_REVOKED
ORGANIZATION_ACCESS_REVOKED
MFA_ENABLED
MFA_DISABLED
```

Treat audit history as append-oriented.

---

## 17. Transactional Outbox

Each owning service has its own outbox table.

```text
OutboxEvent
- UUID id
- String aggregateType
- UUID aggregateId
- String eventType
- long aggregateVersion
- JSON payload
- Instant createdAt
- Instant publishedAt
- int attempts
- Instant nextAttemptAt
- String lastError
```

Domain mutation and outbox insertion occur in the same MySQL transaction.

The publisher must not hold a DB transaction open while performing slow Redis/Kafka network calls.

Claim committed batches, publish, then mark completion.

Use `FOR UPDATE SKIP LOCKED` or an equivalent claim mechanism where appropriate.

Redis DEL/update operations should be idempotent.

Kafka events should include:

```text
eventId
aggregateId
version
eventType
occurredAt
```

Consumers must tolerate duplicates and stale/out-of-order versions.

---

## 18. Authorization Cache Architecture

Preferred flow:

```text
Request
  ->
service validates JWT locally
  ->
extract account/session identity
  ->
Caffeine L1
  -> miss
Redis shared L2
  -> miss
IAM internal entitlement endpoint
  ->
IAM MySQL
  ->
IAM writes Redis
  ->
service fills Caffeine
```

Rules:

- IAM owns the source-of-truth authorization DB.
- IAM is the only writer/deleter of shared IAM Redis authorization entries.
- Domain services read shared Redis but never mutate IAM authorization state.
- Domain services own their local Caffeine caches.
- Kafka security events invalidate local Caffeine entries.
- Use version numbers to prevent stale cache/event races.
- New service instances start with empty Caffeine; do not bulk preload.
- Use bounded caches, TTLs, TTL jitter, aggressive network timeouts, circuit breakers, and single-flight/request coalescing where useful.
- For sensitive authorization, fail closed if current permission cannot be established.

Redis Cluster must be accessed using a cluster-aware client. Do not hardcode individual Redis node behavior into application logic.

---

## 19. Service-to-Service Communication

Use:

- HTTP/REST or gRPC for immediate synchronous operations.
- Kafka for asynchronous propagation and domain events.

Never access another service's database.

Use service discovery/load balancing; do not hardcode instance IPs.

Every synchronous call needs:

- timeout
- appropriate circuit breaker
- carefully bounded retry only when safe/idempotent
- observability

Avoid long synchronous service chains.

Service identity is separate from user identity.

Use OAuth2 client credentials or another short-lived service identity mechanism.

If a downstream service must authorize the original user, use a delegated/on-behalf-of/token-exchange design. Do not trust arbitrary `X-User-Id` headers.

### Internal authorization implementation

- `POST /api/v1/internal/authorization/organization` (using the configured API base
  path) authenticates a service with a separate trusted issuer/audience, HTTPS JWKS,
  RS256 signature, allowlisted subject and `iam.authorization.read` scope. Service
  JWTs require issued/expiry timestamps, at most five minutes of lifetime and no
  user-session `sid`. The route is disabled by default and fails closed. Trusted
  service tokens are obtained from the configured external service identity issuer;
  this slice does not introduce an IAM service-token issuance endpoint.
- Local integration uses Keycloak 26.8.0 in the existing `unidocs-auth` Compose
  project as that external issuer, with a dedicated schema/user on reused MySQL
  and private `unidocs_internal_network` connectivity. Document uses client credentials
  and RS256 service JWTs with the fixed service subject, IAM audience/scope,
  120-second lifetime and no user `sid`. Local TLS uses a dedicated truststore;
  production requires stable HTTPS DNS, trusted certificates and managed secrets.
  The requested local administration mode runs a separate `keycloak-dev` service
  with `start-dev`, localhost HTTP port 8082 and development admin credentials.
  The TLS issuer service is stopped behind the `keycloak-tls` profile. HTTP admin
  availability does not satisfy the HTTPS service-token trust boundary; secure
  issuer integration and Document-to-IAM acceptance remain pending.
- The original user access JWT travels in `X-Delegated-Authorization: Bearer ...`.
  IAM independently verifies its signature/issuer/audience/expiry, derives `sub` and
  `sid` exclusively from that token, and checks the requested account's current grant.
  Neither request identity selectors nor client identity headers establish authority.
  Delegated token expiry is checked again after acquiring session locks, so lock
  contention cannot extend its lifetime.
- Existing session/account-group locks and fresh shared MySQL organization visibility
  checks enforce current session/grant validity, credential versions, active account,
  organization/membership, restrictions and organization authentication policy.
  Successful checks refresh the existing session/grant activity. No cache can grant
  access, and no JWKS/Redis/Kafka network call occurs inside this transaction.
- Responses contain only organization membership ID/role and organization/membership
  versions, account/organization selectors and the check instant. `expiresAt` equals
  `checkedAt`: this is point-in-time evidence, not a reusable permission lease. HTTP
  responses use `Cache-Control: no-store`. Domain services must obtain a fresh check
  for protected operations until their version/revocation-aware cache contract exists.
- Organization membership evidence does not confer workspace/document or group
  permissions; those checks remain with their owning services. No schema mutation or
  outbox event is required for this read. Existing session-expiry revocation keeps its
  transactional audit behavior. Bounded outcome/latency metrics exclude identities,
  headers and credentials. Deployment requires TLS and configured service trust.
- The same service/user trust boundary protects `/internal/authorization/account`
  and `/internal/authorization/group`. Account evidence establishes only the current
  selected account grant and its verified user owner, session, authentication method
  and credential version. Group evidence requires current organization authority
  plus a bounded, effective group membership anchored to that organization membership,
  valid membership times, active group/ancestor state and applicable academic enrollment
  rules. Organization ownership does not substitute for group membership, and group
  role names never grant organization administration. Multiple ambiguous active results
  fail closed. All evidence retains the immediate-expiry/no-store contract.
- Document OWNER access compares verified owner evidence with its own workspace owner;
  ORGANIZATION/GROUP access uses the corresponding IAM evidence; RESTRICTED access
  additionally requires current Document-owned WorkspaceMember authority. Document
  remains responsible for workspace/resource status and visibility across all paths.

---

## 20. Stateless Spring Services

Spring Boot instances must be horizontally replaceable.

Required durable state must not live only in JVM/pod memory.

Caffeine is acceptable because it is disposable.

Use stateless Spring Security request handling for access JWTs, for example with `SessionCreationPolicy.STATELESS`.

Refresh/session/account-grant state must be shared/durable.

Killing a pod must not lose required business/security state.

---

## 21. Scaling Directory and Document Metadata

A large `directories` table is expected and acceptable when indexed and partitionable.

Normal directory queries must be scoped by `workspaceId`.

Example:

```sql
SELECT ...
FROM directories
WHERE workspace_id = :workspaceId
  AND parent_directory_id = :parentDirectoryId
  AND status = 'ACTIVE'
  AND (name, id) > (:lastName, :lastId)
ORDER BY name, id
LIMIT :limit;
```

### Horizontal scaling boundary

Use `workspaceId` as the primary metadata locality/sharding key.

All directory/document metadata for one workspace should normally live on the same metadata shard.

Do not shard collaborative workspaces by user.

Future topology:

```text
Document Service
    ->
Shard Router
    ->
workspaceId -> virtual bucket -> physical MySQL shard
```

Prefer virtual buckets/consistent placement over permanently using:

```text
hash(workspaceId) % physicalShardCount
```

because changing physical shard count would otherwise cause excessive movement.

A future placement model may contain:

```text
WorkspacePlacement
- workspaceId
- bucketId
- shardId
- region
- placementVersion
```

Cache placement mappings in Caffeine/Redis because they change infrequently.

Use globally unique IDs. UUIDv7 is preferred for new high-volume metadata if the chosen Java/library/database implementation supports it cleanly.

Do not pre-create large numbers of empty default directories. Lazy/virtual roots are acceptable.

---

## 22. Elasticsearch

Elasticsearch is for:

- file/directory name search
- extracted document text
- MIME type filtering
- tags
- metadata search
- workspace-scoped search
- authorized discovery

It is not authoritative for:

- whether a document exists transactionally
- directory hierarchy truth
- membership truth
- authorization
- exact security-sensitive counters

Search indexing is asynchronous and may lag MySQL.

The search index must contain sufficient authorization-scope information and queries must enforce the same visibility rules as the primary application.

Revoked organization/workspace content must disappear from search results without leaking names/snippets/metadata.

---

## 23. Final Logical Class Relationships

```mermaid
classDiagram
direction TB

class PendingRegistration
class RegistrationVerification
class User
class UserProfile
class UserContact
class UserPreference
class UserAccount
class LoginIdentity
class AccountCredential
class AccountGroup
class AccountGroupMember
class UserSession
class SessionAccountGrant
class SessionGrantPolicy
class Organization
class OrganizationAuthPolicy
class OrganizationMembership
class Group
class GroupMembership
class GroupJoinRequest
class Workspace
class WorkspaceMember
class WorkspaceJoinRequest
class Directory
class Document
class DocumentVersion
class DocumentFavorite
class AccessPolicy
class StepUpGrant
class Notification
class SecurityAuditEvent
class OutboxEvent

PendingRegistration "1" *-- "0..*" RegistrationVerification
PendingRegistration ..> User : provision
PendingRegistration ..> UserAccount : provision

User "1" *-- "0..1" UserProfile
User "1" *-- "0..*" UserContact
User "1" *-- "1" UserPreference
User "1" --> "1..*" UserAccount
User "1" --> "1" AccountGroup

UserAccount "1" *-- "1..*" LoginIdentity
UserAccount "1" *-- "0..*" AccountCredential

AccountGroup "1" *-- "1..*" AccountGroupMember
AccountGroupMember "*" --> "1" UserAccount

AccountGroup "1" --> "0..*" UserSession
UserSession --> UserAccount : login account
UserSession "1" *-- "1..*" SessionAccountGrant
SessionAccountGrant "*" --> "1" UserAccount
SessionGrantPolicy ..> SessionAccountGrant

Organization "1" *-- "0..*" OrganizationAuthPolicy
Organization "1" --> "0..*" OrganizationMembership
UserAccount "1" --> "0..*" OrganizationMembership

Organization "1" *-- "0..*" Group
Group "0..1" --> "0..*" Group : hierarchy
Group "1" --> "0..*" GroupMembership
UserAccount "1" --> "0..*" GroupMembership
Group "1" --> "0..*" GroupJoinRequest
UserAccount "1" --> "0..*" GroupJoinRequest

UserAccount "1" --> "0..*" Workspace : personal
Organization "1" --> "0..*" Workspace
Group "1" --> "0..*" Workspace

Workspace "1" --> "0..*" WorkspaceMember
UserAccount "1" --> "0..*" WorkspaceMember
Workspace "1" --> "0..*" WorkspaceJoinRequest
UserAccount "1" --> "0..*" WorkspaceJoinRequest

Workspace "1" --> "0..*" Directory
Directory "0..1" --> "0..*" Directory : parent / children
Directory "1" --> "0..*" Document
Workspace "1" --> "0..*" Document
Document "1" *-- "1..*" DocumentVersion

UserAccount "1" --> "0..*" DocumentFavorite
Document "1" --> "0..*" DocumentFavorite

AccessPolicy "1" --> "0..*" StepUpGrant
UserSession "1" --> "0..*" StepUpGrant
UserAccount "1" --> "0..*" StepUpGrant

AccountGroup "1" --> "0..*" Notification
Notification --> UserAccount : affected account
Notification --> Organization : related organization

User "1" --> "0..*" SecurityAuditEvent
UserAccount --> SecurityAuditEvent
UserSession --> SecurityAuditEvent

OutboxEvent ..> OrganizationMembership
OutboxEvent ..> GroupMembership
OutboxEvent ..> WorkspaceMember
OutboxEvent ..> Document
OutboxEvent ..> Notification
```

---

## 24. Auth Service Development Sequence

Implement the IAM/Auth service as small vertical slices.

### Phase 1 — Bootstrap

- Spring Boot project
- Java 25
- Spring Boot 4.1.1
- Maven 3.9.16
- Spring Security
- JPA
- MySQL
- Flyway
- validation
- Actuator
- Testcontainers
- structured errors/logging
- UUID/time conventions
- baseline CI tests

#### Versioned login audit decision

- LOGIN_SUCCEEDED and LOGIN_FAILED retain their authoritative security_audit_event
  rows and additionally store a version-1 typed JSON envelope in that same row.
  Historical and other audit types remain valid without an envelope; no automatic
  backfill or historical publication occurs.
- The login audit row and matching SECURITY_AUDIT outbox row commit in the same
  caller transaction. Their UUID event IDs are identical; aggregate ID is the
  immutable audit event ID and aggregate version 1 identifies this immutable fact,
  not account/authorization state. Audit/outbox persistence failure rolls back login
  session/grant/refresh mutation; no credentials are returned after failure.
  Existing failed-login transactions commit before returning the authentication error.
- Only successful credential verification supplies an ACCOUNT actor. Failed login
  events have UNKNOWN actor, with an optional known attempted-account target; the
  target is not a claim of authenticated identity. No login selectors, credentials,
  token values, network/device data or unchecked tenant identity enter the envelope.
  Canonical request/trace IDs are optional correlation only.
- SECURITY_AUDIT records publish to a distinct restricted Kafka audit topic, default
  iam.security-audit.v1; sharing the ordinary domain topic is rejected. Existing
  bounded outbox leases/retry backoff apply, without network I/O in domain transactions.
  Kafka/collector outages retain pending delivery and do not roll back committed login.
- Downstream audit consumers must deduplicate by event ID and validate schema version;
  consumer archival/projection, formal retention/legal hold/deletion/access policies,
  remaining event taxonomy and bulk-session audit enrichment are later slices.
  No public audit-query API or automatic audit deletion is introduced.

#### Private metrics management decision

- The optional metrics Spring profile creates a separate management listener on
  loopback port 9091. Enabling scrape authentication fails startup unless the listener
  is separate and loopback-bound and its dedicated URL-safe secret is 32–256 characters.
- GET /actuator/prometheus accepts only the dedicated opaque Bearer scrape credential.
  App JWTs and Basic credentials cannot authorize a scrape; scrape credentials cannot
  authorize application APIs or other management operations. The listener is stateless.
- Health/readiness/liveness remain anonymous with hidden details on the private listener.
  Optional main-port /livez and /readyz probes preserve application-port health checks.
  Without the profile, existing application management security remains in force.
- Credentials come from injected secrets/environment; they are never persisted as
  domain data, logged, or included in metrics/traces. Loopback HTTP is intended for
  co-located monitoring sharing the process/pod network namespace; no management port
  is published by the optional Compose override. External dashboards/alerts are deployed
  separately and do not influence application readiness.

#### Phase 1 implementation decisions

- The Java root package is `com.unidocs.auth`. Add capability packages and their
  layers when implementing their vertical slices; no future domain placeholders.
- Application API mappings use `api.version.base-path`, default `/api/v1` in
  `application.properties`. Security matchers, browser CORS, rate-limit routing and
  API selection URLs follow the same configured prefix. The prefix must be a
  canonical absolute path with no trailing slash, wildcards or URI/query syntax.
  Changing the prefix moves these endpoints; it does not add a legacy alias or
  alter request/response DTOs. Standard JWKS discovery and Actuator paths stay fixed.
- Flyway owns the schema. Hibernate uses `ddl-auto=validate`, with Open Session in
  View disabled. The initial migration establishes history without domain tables.
  Deployment provisions the dedicated IAM MySQL database and credentials.
- Persist domain UUIDs as `BINARY(16)` and timestamps as UTC `Instant` values.
  Application services use an injectable UTC `Clock`. UUIDv7 selection is deferred
  until a high-volume domain record is implemented; request IDs use random UUIDs.
- During bootstrap, only GET health/liveness/readiness probes permit anonymous
  access. Readiness checks MySQL. Other routes deny access, including operational
  info/Prometheus endpoints, until explicit authentication is implemented.
- Spring Security is stateless with no basic/form/cookie authentication, generated
  development credentials, request cache or logout endpoint. CSRF is disabled for
  this API baseline and must be reconsidered if cookie authentication is added.
- Errors use sanitized problem JSON. Logs use Logstash JSON with generated request
  IDs in MDC and `X-Request-Id`; request values and exception messages are not logged.
- MySQL 8.4 Testcontainers tests are mandatory in the normal Maven test lifecycle.
  CI runs the Maven 3.9.16 wrapper with Java 25 and Docker; no infrastructure skips.
- Local Maven tests (with `CI` unset) share and reuse one manually started MySQL
  Testcontainer across classes and runs. Ryuk is disabled locally and the developer
  stops MySQL manually. Registration test data is cleared before each test while
  retaining Flyway history. CI disables reuse and enables Ryuk cleanup.
- Local MySQL integration testing can reuse the existing `unidocs-auth` Compose
  MySQL through the optional `test` profile and persistent `test-runner` tooling
  service (`scripts/test-compose.ps1`). Source is mounted read-only, build outputs,
  Maven cache and a generated test-database secret use separate reusable volumes,
  and the runner has no Docker socket. Tests use a distinct `auth_service_test`
  database/user with privileges limited to that schema, leaving development data
  intact. Test-only `AUTH_TEST_DB_URL/USERNAME/PASSWORD` settings are all-or-none;
  external mode accepts only that schema and approved single-host JDBC options,
  skips creating a MySQL Testcontainer, and checks the actual selected schema
  before cleanup. CI/default infrastructure tests retain Testcontainers (using the
  same isolated schema); the optional Compose runner covers MySQL, Redis-only and
  isolated suites, not the older combined Redis/Kafka or S3 bases. Local
  database tests remain sequential and reusable containers stay running.
- The local Docker Compose stack runs a Java 25/Maven-wrapper multi-stage build,
  a non-root Java 25 JRE application, and isolated MySQL 8.4.8. A one-shot setup
  preparation script initializes or migrates all local settings and credentials into
  one ignored root `.env`, preserving existing values. Keys, certificates and
  generated credential-file adapters reside in `.secrets/`; adapters are derived
  from `.env` and must not be edited separately. Containers receive database and
  service credentials through environment injection and PEM keys through read-only
  mounts. MySQL root and application identities remain distinct. Retain `.env`,
  `.secrets/` and database volumes together. Readiness gates app startup; published
  ports bind to localhost. SMTP is
  explicitly configured separately. This is local development packaging, not a
  production secret-management or deployment policy, and adds no Redis/Kafka consumers.
- Infrastructure preparation adds Redis 8.2.10 and Kafka 4.1.2 to that local stack.
  Redis uses bounded, disposable storage without persistence; Kafka is a single
  KRaft broker/controller with persistent logs and replication factor 1. Neither
  publishes a host port. Topic auto-creation is disabled. Production authentication,
  TLS and Kafka replication remain deployment concerns.
- Spring provides Redis and Kafka clients and a bounded Caffeine cache manager
  (10,000 entries per cache, 30-second write TTL, statistics, empty on startup).
  Caffeine lives in the JVM, not in a separate container. Infrastructure preparation
  does not cache mutable authorization: versioned projection/invalidation remains
  its own vertical slice. Outbox delivery is specified below. MySQL remains authoritative.
- Compose opts into Redis/Kafka health and includes them in readiness. Standalone
  runs leave these optional checks disabled until infrastructure is configured.
  Redis connect/command waits are one second; Kafka metadata probes wait at most
  two seconds and return sanitized health results. Infrastructure integration tests
  use reusable Redis/Kafka Testcontainers locally, with normal Ryuk cleanup in CI.

### Phase 2 — Registration

Implement:

- PendingRegistration
- RegistrationVerification
- verification expiration
- attempt limiting
- password hashing
- provisioning transaction
- registration integration tests

Initial endpoints:

```text
POST /api/v1/registrations
POST /api/v1/registrations/{id}/verify
```

#### Phase 2a — Pending registration and verification decisions

- The first registration slice supports Personal accounts with email identities.
  Its request contains `displayName`, `email`, and `password`; organization/invitation
  registration and additional profile fields are deferred to their own slices.
- Personal registration canonicalizes the email in its immutable request DTO before
  HTTP/service Bean Validation, so surrounding whitespace is accepted and the
  same `strip()`/`Locale.ROOT` lowercase value reaches lookup, delivery and storage.
  Passwords are preserved exactly, including meaningful surrounding whitespace.
  Client-supplied role, authority, identifier, status, enabled/locked, credential
  version/hash and timestamp fields do not bind to the registration/verification/
  completion DTOs or influence provisioned defaults. Pending rows may still
  duplicate; the existing canonical LoginIdentity unique index resolves final
  identity conflicts transactionally. No additional registration schema is needed.
- Email identifiers are trimmed and lowercased using `Locale.ROOT`. Passwords are
  preserved verbatim, require 12–128 characters, and use Spring Security PBKDF2
  SHA-256 (310,000 iterations, random 16-byte salt, 256-bit output).
- Registrations expire after 24 hours. Email verification uses a random six-digit code, stored only as a salted BCrypt hash, and expires after five minutes.
  A verification permits at most five attempts. Token comparison is constant-time.
  Random UUID identifiers are stored as `BINARY(16)` for this initial slice;
  UUIDv7 remains deferred until high-volume requirements justify an implementation.
- Verification locks the pending registration row and commits failure attempts
  and expiration state before reporting failure. Tokens are single-use; retries
  after successful verification receive the same generic 400 as invalid tokens.
  Successful verification ends at `VERIFIED` and creates no User, UserAccount,
  memberships or sessions. Transactional, idempotent provisioning is the separate
  Phase 3 use case below.
- Email delivery uses explicitly enabled/configured SMTP with required STARTTLS
  and bounded connection/read/write timeouts. Disabled delivery returns sanitized
  503 before persistence; enabling SMTP without its required host/sender fails
  startup. The plaintext token exists only in memory and
  the delivered email, never in the API response, database, URL or application logs.
- SMTP runs synchronously after the MySQL transaction commits. A delivery failure
  returns sanitized 503 and leaves a pending record which cannot authorize access.
  The client may submit a new registration; duplicate pending email registrations
  are intentionally allowed and confer no identity ownership. Provisioning must
  enforce uniqueness of normal LoginIdentity identifiers transactionally.
  Resend, durable delivery retry, cleanup and registration-wide rate limiting are
  deferred. This slice has no downstream authorization mutation to propagate.
- Only POST registration creation and token verification are newly public.
  Other API/operational routes retain the bootstrap security policy. Bounded metrics
  count creation, verification success/failure/expiration and delivery failure,
  without identifiers or secrets as metric labels.

### Phase 3 — Core Identity

Implement:

- User
- UserProfile
- UserContact
- UserPreference
- UserAccount
- LoginIdentity
- AccountGroup
- AccountGroupMember

#### Phase 3 implementation decisions

- `POST /api/v1/registrations/{id}/verify` continues to commit only `VERIFIED`.
  A separate `POST /api/v1/registrations/{id}/complete` accepts the same email token
  in a redacted request body and provisions only a verified Personal registration.
  The registration UUID alone is not proof of control. The stored token hash is
  compared in constant time, and the verification must already be `VERIFIED`.
- The token is single-use for verification. After verification it remains a
  capability for completion and idempotent completion retries until the original
  24-hour registration deadline, even after the five-minute verification window.
  It cannot authenticate, create a session, or authorize account resources.
  Invalid proof/state/deadline receives sanitized 400; an already owned login
  identifier receives sanitized 409. Completion retries always require proof.
- Completion locks the registration and creates User, an empty optional-field
  UserProfile, a primary verified email UserContact, UserPreference, a Personal
  UserAccount, LoginIdentity, AccountGroup, and its initial AccountGroupMember in
  one MySQL transaction. The existing password hash is copied without rehashing.
  LoginIdentity starts at credential version 1. UUIDs remain random `BINARY(16)`.
- LoginIdentity has a unique `(type, identifier)` index; emails use the existing
  trim/`Locale.ROOT` lowercase normalization and binary collation, avoiding extra
  accent folding. Concurrent duplicate completions roll back the losing identity
  transaction and return 409. No email alias/provider-specific rewriting is used.
- Completion stores the resulting user/account/group IDs on PendingRegistration,
  with constraints linking `COMPLETED` to those IDs and its timestamp. Retries
  return the original result without duplicate records. Any failed provisioning
  rolls back all identity/audit writes and leaves `VERIFIED` available for retry
  within the registration deadline. UTC completion times use microsecond precision.
- Initial group linking has `linkMethod=REGISTRATION`, is self-attributed to the
  new account, and must have the same human owner. A primary key on member account
  ID enforces at most one AccountGroup. The preferred account is the Personal
  account; a composite FK enforces preference ownership. Preference defaults are
  theme SYSTEM, time zone UTC, no locale override, email/push notifications off,
  and security notifications on. Preference and linking confer no permissions.
- Append-oriented `REGISTRATION_COMPLETED` and `ACCOUNT_LINKED` audit rows are
  inserted in the same transaction, containing IDs, event type and UTC time only.
  This slice has no downstream projection/resource provisioning to propagate;
  outbox/Kafka integration remains a later slice when asynchronous consumers exist.
  Login, sessions, memberships, documents and account-root grants remain deferred.
- Hibernate JDBC error logs are disabled alongside SQL/bind logs because duplicate
  key messages can expose identifiers. Provisioning metrics use bounded outcome
  labels (success, replayed, invalid, conflict, failure), never IDs or secrets.
- Reusable MySQL integration tests now clear all identity, registration and audit
  test data before each test while preserving schema/Flyway history. They remain
  sequential; parallel suites require isolated schemas before being enabled.

### Phase 4 — Login / JWT / Session

Implement:

- asymmetric signing
- JWKS
- access token issuance
- login
- UserSession
- initial SessionAccountGrant(authMethod=LOGIN)
- refresh mechanism with rotation/replay protection
- logout
- session revocation

Endpoints:

```text
POST /api/v1/auth/login
POST /api/v1/auth/refresh
POST /api/v1/auth/logout
GET  /api/v1/me
GET  /api/v1/me/accounts
```

#### Phase 4 implementation decisions

- The Personal email/password login checks active identity, user, account, account
  group and linked membership. Password verification happens outside the transaction;
  locked state/hash/version are rechecked before creating a session. Each successful
  login creates a separate UserSession and exactly one LOGIN SessionAccountGrant.
- Sessions and initial grants have a 12-hour absolute deadline. Grants expire after
  30 idle minutes. Successful IAM identity/navigation reads and refreshes update
  activity without extending the absolute deadline. Expired grants cannot be revived
  by refresh. Login/refresh/me checks are current MySQL checks, including credential
  version. Preferred account remains navigation only; other linked accounts stay locked.
- Session persistence uses explicit JDBC mappings and domain records alongside the
  existing JPA identity mappings. Application transactions use READ_COMMITTED and
  lock session before refresh/grant records. Security writes/audits and local signing
  are in one transaction; no remote calls occur while database locks are held.
- Refresh credentials consist of a UUID selector plus 256 random secret bits. Only
  SHA-256 hashes are stored. Rotation consumes each credential and stores its replacement;
  retained consumed records allow replay detection. Proven replay commits revocation of
  the whole session, every grant and refresh credential before returning generic 401.
  Wrong secrets never revoke a legitimate session. There is no concurrent/retry grace
  window: clients must serialize refreshes, and a lost response requires a new login.
  Cleanup must retain consumed records until the session's absolute expiry.
- Logout revokes the same durable family transactionally. It is idempotent for the
  matching login account/session while the signed access token remains unexpired.
  It requires no live unlock because it only reduces access. Other session/account
  pairs fail with 401. Independent sessions remain valid.
- RS256 access tokens last five minutes and contain only sub (login account UUID),
  sid, iss, aud, iat and exp. Validation requires those UUID claims, configured issuer
  and audience, kid, valid issuance/expiration/not-before and at most five-minute lifetime; clock
  skew is zero. JWT claims supply no permission authorities. JWT request processing
  remains stateless. Sensitive downstream authorization still requires live server
  state; JWT validity alone is insufficient.
- Production loads a configured PKCS#8 RSA private key, matching X.509 public key
  and stable kid (minimum 2048 bits). No production ephemeral key generation is allowed.
  Retained public keys support rolling rotation and old-token verification. The public
  endpoint is `/.well-known/jwks.json` with 60-second cache lifetime; it never exposes
  private material. Retain old keys through access-token lifetime and validator caches.
  Tests generate in-memory keys only; durable sessions/refreshes survive JVM replacement.
- /me exposes current human/login-session identity and navigation preference only.
  /me/accounts uses UUID keyset pagination (1–100, default 50) scoped to linked active
  accounts in the session group and reports current unlock state. It returns no
  organization/workspace permission graph or resource content.
- Login success/failure, session revocation and refresh replay audits commit with
  their security mutations and contain only IDs/type/time. Unknown-identity failures
  have nullable identity IDs, never supplied email/password. Metrics use bounded
  labels. Asynchronous propagation/outbox remains deferred until resource/projection
  consumers exist; current authorization is limited to IAM identity/navigation.
  Brute-force throttling remains the hardening phase. Reusable tests now clear session,
  grant and refresh rows before identity rows, keeping MySQL/Flyway history alive.

### Phase 5 — Linked Account Unlock


Implement:

- AccountCredential
- PIN/password/passkey abstraction
- account linking proof
- unlock endpoint
- multiple simultaneous SessionAccountGrants
- idle/absolute expiration
- preferred account/fallback logic

#### Phase 5 linked-account implementation decisions

- Account-root challenges have a two-minute lifetime capped by session expiry, five
  attempts, and a durable binding to session/account/purpose/method/credential ID and
  version/policy version. The public challenge UUID is not proof. A consumed challenge
  cannot be replayed. The API is POST /api/v1/accounts/{accountId}/challenges and
  POST /api/v1/accounts/{accountId}/challenges/{id}/complete. Bodies/responses are redacted
  or contain no secrets; responses use no-store. Authenticated-but-forbidden target
  operations/proofs receive sanitized 403; invalid session context receives 401.
- PASSWORD proof verifies existing LoginIdentity; its hash is never duplicated.
  AccountCredential currently implements additional PIN proof using salted PBKDF2,
  a separate credential ID/version and account-wide failure counter. Five failed PIN
  proofs across challenges/sessions lock it for 15 minutes. Successful proof or PIN
  replacement resets failures. Password/PIN use AccountProofVerifier; PASSKEY is a
  reserved method that fails closed pending a real WebAuthn adapter. Other factors
  are future adapters, not accepted placeholders.
- SET_PIN requires a currently unlocked target and a fresh PASSWORD challenge. PINs
  contain 6–12 digits and are stored only as salted hashes. Replacement increments
  version and revokes all prior PIN grants across sessions. Existing PASSWORD/LOGIN
  grants survive. If the changing session's PIN grant was revoked, its fresh password
  proof can create a replacement PASSWORD grant.
- Successful UNLOCK consumes proof and creates/replaces exactly one target grant,
  preserving concurrent grants for other accounts. Grants store credential source,
  credential ID/version and policy version. Source-specific validity avoids comparing
  PIN versions against unrelated LoginIdentity versions. Expiry is checked at use time;
  fresh proof can renew a target grant while another valid grant sustains the session.
- GLOBAL SessionGrantPolicy is durable/versioned, defaults to idle 30 minutes and
  absolute 12 hours, and requires multi-account grants plus reauthentication. Each
  grant's absolute deadline is capped by its session deadline; activity never extends
  it. Stale policy grants/challenges fail closed. Organization-scoped overrides and
  policy administration will arrive with organization/security policy features.
- Immutable JWT sub/sid identify the original login account/session; they are not a
  global active-account selection. Any current linked, available, source/version/policy
  valid grant can sustain identity/navigation/refresh. Losing the original LOGIN grant
  does not terminate the umbrella session while another valid grant survives. No usable
  grant causes durable session/family revocation before returning 401 at the next check.
- LINK requires target proof and the same established human owner, plus a disconnected
  or absent link. It never moves another human's account, creates a target grant, changes
  preference, or grants organization permissions. Merging independently registered Users
  and organization identity provisioning are separate future slices. Disconnected accounts
  require re-linking for current group-based login; standalone-account sessions remain
  future work and must not implicitly restore a disconnected link.
- UNLINK requires target proof, disconnects it, revokes its grants across sessions and
  invalidates pending target challenges in the same transaction. The invoking session is
  revoked if no valid grant survives; other affected sessions are revoked lazily on their
  next authoritative IAM read/refresh. Remaining valid grants keep their session alive.
  Preference fallback never grants unlock: choose oldest available Personal account,
  with UUID as creation-time tie-breaker; otherwise choose the sole available organization
  account, or clear preference for an account selector when several remain (or none).
  UserPreference is nullable to represent no selected account.
- PUT /api/v1/me/preferred-account changes an owned, linked, available account's navigation
  preference only, including locked targets. /me/accounts reports current grant validity
  from either credential source. No account selection exposes resource permissions.
- Proof checks/PIN hashing occur before the write transaction, then locked identity/hash/
  version, challenge binding, ownership/link and policy are rechecked. Session/group locks
  precede proof/grant locks; login acquires group before identity. Public authentication
  and account use cases reject inherited transactions before proof work. Failure attempts/expiry
  and security audits commit before generic denial; a failed grant write rolls back proof
  consumption and all writes. Concurrent consumption succeeds once. Audits contain IDs,
  event type/time only. Outbox projection propagation is still deferred while authorization
  is limited to IAM identity/navigation without asynchronous resource consumers.

### Phase 6 — Organizations


Implement:

- Organization
- OrganizationAuthPolicy
- OrganizationMembership
- invitations/provisioning
- revocation
- auth versioning
- session-grant revocation
- fallback
- durable notification event

Organization bootstrap implementation decisions (first Phase 6 slice):

- POST /api/v1/organizations requires explicit accountId and requestId. The selected
  account must have a current LOGIN/PASSWORD grant in the caller's server session.
  The initial OWNER membership activates for that existing account; dedicated
  organization-account provisioning and invitations remain separate slices.
- The founder's officialEmail comes from the human's verified primary UserContact.
  The bootstrap policy enables PASSWORD, disables PIN unlock, and does not require
  MFA. Policy administration is not exposed. Reads fail closed for disabled policy,
  MFA-required policy, or an email-domain restriction until those proofs are supported.
- Creation stores account-scoped request idempotence and a normalized payload hash.
  Repeating a matching request returns the same organization (HTTP 201); changing
  the payload or colliding with a global slug returns a sanitized 409. A retry must
  still pass current grant, membership, organization and policy authorization.
- Organization creation, ACTIVE OWNER membership version 1, organization auth
  version 1, both audit records and a pending ORGANIZATION_CREATED outbox envelope
  commit in one MySQL transaction. The envelope carries IDs, versions and timestamp,
  without credentials or personal contact data. Phase 9 now supplies publication.
- GET /api/v1/organizations/{id} and cursor-paginated GET /api/v1/me/organizations
  require an explicit unlocked account and current ACTIVE membership/organization
  plus usable policy. Group linking, navigation preference and JWT alone confer
  no organization access. This does not implement workspace/document authorization.
- No revocation mutation is exposed by this slice. Full revocation must implement
  the complete section 9 propagation, grant revocation, notification and fallback
  contract before being called complete. Phase 8 now supplies the first organization
  snapshot projection; it does not complete revocation propagation.

Organization invitation implementation decisions (second Phase 6 slice):

- POST /api/v1/organizations/{organizationId}/invitations takes an explicit
  unlocked issuer accountId and recipient email. Current OWNER/ADMIN membership,
  usable organization policy and a LOGIN/PASSWORD grant are required. The slice
  delegates MEMBER activation only; clients cannot request an administrative role.
- Invitations last 24 hours and store only a SHA-256 hash of a random 256-bit proof.
  SMTP receives the proof after transaction commit. API responses, audits and outbox
  envelopes contain no plaintext proof. SMTP is separately enabled/configured and
  issuance fails closed when no provider exists. Transport failure returns 503 after
  commit; reissuing for the same normalized organization/email supersedes the old
  pending invitation and sends a fresh proof. At most one PENDING invitation exists
  for that organization/email. Issuance is a new request, not an idempotent resend.
- POST /api/v1/organizations/{organizationId}/invitations/{id}/accept requires the
  proof in a redacted body and an explicitly unlocked LOGIN/PASSWORD account. The
  human's verified primary contact and the selected account's active EMAIL identity
  must both match the invited address. The account must already be provisioned by
  verified registration; this slice creates no User, account, credentials, linking,
  session grants or preference changes. Dedicated organization-account provisioning
  uses the separate endpoint documented below; invited registration remains future work.
- Issuer account/human availability and linking, membership ID/version, ACTIVE status and OWNER/ADMIN role are rechecked
  at first acceptance along with current organization policy. Incorrect-email actors
  cannot consume another recipient's proof attempts. Five failed proofs permanently
  fail the invitation; lazy expiration/failures and security audits commit before
  generic 403. Policy changes and issuer revocation/version changes fail closed.
- Activation inserts ACTIVE MEMBER membership version 1, increments the organization
  authorization version, consumes/binds the invitation, records the audit, and queues
  invitation-state and membership-activation outbox events in one transaction.
  Matching retries return the original membership without repeated mutation/events,
  including after the original deadline, while current target membership/policy remain
  valid. They still require the bound account and proof. Existing/revoked memberships
  cannot be replaced or resurrected through another invitation.
- Operations lock the caller session/group/grant, then organization/policy, then
  invitation and membership. Organization locks serialize invitation replacements
  and activation; no lock is acquired on another human's account group. Membership
  mutation paths must retain that organization lock order. Kafka/projection delivery,
  full revocation, administrative role changes and invitation UI remain deferred.

Dedicated organization-account implementation decisions (third Phase 6 slice):

- POST /api/v1/organizations/{organizationId}/invitations/{id}/provision-account
  accepts accountId, token, displayName and a new independent password. The caller
  must be an already verified human with an explicit current LOGIN/PASSWORD source
  account grant. The invitation proof verifies the official organization email, which
  may differ from the human's verified primary contact. No unverified registration
  or account belonging to another human can participate.
- Provisioning creates a COMPANY/UNIVERSITY/CUSTOM UserAccount scoped by non-null
  organizationId, an ACTIVE MEMBER membership with that verified official email,
  an independently hashed ACCOUNT_ID LoginIdentity, and an INVITATION link in the
  human's existing AccountGroup. Personal accounts have null organizationId. A unique
  (userId, organizationId) constraint bounds organization roots; any existing human
  membership, including a revoked or legacy Personal membership, blocks provisioning.
  This slice does not convert existing memberships or transfer OWNER authority.
- Anonymous POST /api/v1/auth/accounts/{accountId}/login accepts password and identifies
  only that account's ACCOUNT_ID identity; existing global Personal EMAIL login stays
  unchanged. Credentials are never copied or linked. Direct login creates exactly one
  LOGIN grant, and JWT claims remain sub, sid, iss, aud, iat and exp. Provisioning
  itself creates no session/grant, changes no preference, and leaves the root locked.
  PASSWORD challenges can unlock it in an existing umbrella session. PIN grants also
  require current organization allowPinUnlock policy.
- Account creation, membership activation, linking, invitation consumption/source
  binding, organization authorization-version increment, audits and ID/version-only
  outbox events commit together. Matching retries return the original account only
  with the bound source account, proof, name and independent password, and current
  membership/policy. They do not rotate credentials or restore revoked membership.
  Acceptance and provisioning cannot consume the same invitation in different modes.
  Password hashing and retry verification run outside transactions; final writes
  recheck credential identity/hash/version and all server-side bindings.
- Organization-account login, grants, challenges, preference selection, fallback and
  account listings consult current ACTIVE organization/membership and usable policy
  in MySQL. Unsupported MFA/domain restrictions fail closed. Unavailable roots are
  omitted from listings; another valid account grant can sustain an umbrella session
  with unchanged JWT subject. An org-only session terminates lazily when no grant
  survives. An organization-account inviter must also retain home-organization access
  when inviting into a different organization. These authoritative guards do not
  complete revocation propagation.
- V8 preserves organization.createdByAccountId as an immutable historical UUID audit
  reference without a foreign key. OWNER/ADMIN membership is the authority; the creator
  reference grants no permission. Removing the creator FK avoids a lifetime cycle with
  UserAccount.organizationId's FK, including organizations created from organization
  accounts. API creation still validates the current owned source account/grant.
- Non-personal fallback follows the single-account/selector rule above and never
  unlocks a target. Full organization revocation (Redis/Kafka/Caffeine propagation,
  durable notification, grant mutation and safe navigation), invited registration,
  administrative roles and policy mutation remain separate slices.

### Phase 7 — Groups

Implement:

- Group
- GroupMembership
- GroupJoinRequest
- membership sources
- validity windows
- hierarchical group support as required

#### Group bootstrap decisions (first Phase 7 slice)

- Organization-scoped group management exposes create/detail/cursor-list endpoints.
  This first administrative catalog requires a current OWNER or ADMIN membership and
  an explicit LOGIN/PASSWORD account grant for every operation, including retries.
  Current organization status, membership and authentication policy are checked in
  MySQL. Ordinary members cannot enumerate this administrative catalog. Group
  membership, join requests, customizable roles and validity windows remain separate
  slices; group creation grants no membership, workspace permission or account unlock.
- V10 stores Group in `iam_group` to avoid the SQL GROUP keyword, with BINARY(16)
  identifiers, UTC timestamps, suggested type values, ACTIVE/DISABLED status and
  aggregate version 1. Creation request IDs are scoped by organization and creating
  account. A normalized payload fingerprint makes matching retries idempotent and
  conflicting reuse a sanitized 409. Creator UUIDs are historical audit references.
- An optional parent must already exist and be effectively active in the same
  organization. A composite self foreign key enforces organization locality and a
  check rejects self-parenting. Parents are immutable in this slice, so API creation
  cannot introduce cycles. Root depth is one; depth 32 is the maximum. Reparenting or
  status mutation will require a separate complete hierarchy/propagation contract.
- Group mutations lock the organization root exclusively before current membership
  validation and creation. Reads hold a shared root lock. Future group mutations must
  retain this root locking order. A bounded-depth recursive query only exposes groups
  reachable through ACTIVE ancestors; disabled parents hide descendants. Listings
  use binary UUID keyset cursors and return at most 100 rows, without per-row ancestor
  queries. The recursive catalog currently traverses the organization's hierarchy;
  optimize only if real catalog size/query measurements justify an additional design.
- Group creation, GROUP_CREATED audit and versioned GROUP outbox envelope commit in
  one MySQL transaction. The existing publisher delivers events after commit; no
  network calls occur under database locks. Event metadata excludes group names and
  contact/credential data. Creating an empty group changes no existing entitlement,
  so it does not advance the organization's cached detail version. Future permission
  mutations must version and invalidate their relevant authorization projections.
- API errors use existing sanitized problem details and responses use no-store.
  Bounded group.bootstrap counters describe creation outcomes. Group membership
  changes and complete organization revocation remain unimplemented by this slice.

#### Group discovery and semester enrollment correction

- V15 separates discovery from joining in group_rule; existing ordinary groups keep ORGANIZATION discovery and APPROVAL joining. University COURSE groups default to COURSE_ENROLLMENT. A semester must be bound before student enrollment can grant access.
- Member discovery/detail use current MySQL authority under the organization root lock, active ancestry, current organization/account/grant visibility and student enrollment version. Filtering precedes cursor pagination; metadata and membership flags load in bounded batches. Known UUIDs do not bypass discovery rules.
- OPEN joining creates only the ordinary member role and no group-admin designation. APPROVAL submission and approval recheck current rules and discovery. Old requests can be cancelled/rejected but cannot bypass a changed policy. INVITATION_ONLY uses authenticated, exact-account/organization-membership-bound invitations with deadlines and recipient acceptance; invitations create no entitlement until accepted.
- Organization OWNER/ADMIN may assign canManageGroup explicitly. Scoped group administrators can configure their own group, issue/revoke invitations and review join requests. They cannot confirm student enrollment, create academic semesters, manage other groups or acquire organization administration through a custom role name.
- Academic semesters are immutable UTC intervals unique by organization/code. Course offerings cannot change semester once bound. Trusted enrollment replacement uses an expected snapshot version, up to 100 unique course IDs, a request UUID and canonical fingerprint. The last matching request retries safely; older requests fail the version fence. Replacement revokes previous COURSE memberships, including manual assignments when a student is first classified, and creates COURSE_ENROLLMENT memberships for the current semester without approval. Empty lists are valid.
- Student classification is tied to the exact current organization membership anchor. Staff without a trusted student enrollment record may retain explicit course assignments. Classified students cannot receive manual university COURSE assignments. Student course discovery/effective membership requires the current enrollment source ID/version and current offering/semester window; scheduled cleanup is unnecessary for deadline enforcement.
- Rule/membership/enrollment mutations, audit and versioned outbox records commit together under ordered account-group fences then organization locks. Enrollment emits bounded membership changes plus one organization invalidation. Cache eviction follows commit; MySQL remains authoritative during Redis/Kafka outages. No mutable permission lists enter JWTs.
- Account retention keeps these records until configured purge, which deletes group memberships before enrollment/invitation records. Organization removal or blacklist immediately denies all group paths; restoration does not resurrect revoked course memberships.

#### Administrator-assigned group membership slice

- V13 adds group memberships anchored to the exact organization membership, account,
  organization, and group through database foreign keys. Only current organization
  OWNER/ADMIN accounts with LOGIN/PASSWORD grants may assign or revoke. Assignment
  targets need current organization membership and an available account; linked
  account navigation never supplies authority. Cross-human writes acquire ordered
  account-group fences before locking the organization.
- Direct assignments use ORGANIZATION_ASSIGNMENT sources. Source
  is set by IAM, not claimed by the client. Roles are validated custom strings and
  remain metadata until an explicit permission model exists; a group role named
  OWNER or ADMIN does not grant organization administration. Membership type is
  PERMANENT with no end date, otherwise TEMPORARY. Trusted enrollment is implemented in V15; future directory sync,
  invitation sources require their own use cases. Member join approval is described below.
- Validity is inclusive at validFrom and exclusive at validUntil. Boundaries are
  checked on every effective membership read, without depending on scheduled expiry
  events. API timestamps use MySQL-compatible UTC instants with microsecond precision.
  Groups and every ancestor, account, organization membership, organization and
  authentication policy must remain available. Organization revocation immediately
  kills descendant access; independent group membership revocation stays revoked.
- Assignment request IDs are scoped to organization/administrator account. Matching
  retries return the original current record; changed payloads conflict. One ACTIVE
  assignment per group/organization-membership anchor is allowed. Revoke an expired
  assignment before assigning anew. Revocation retries are idempotent; new assignments
  receive new IDs. Fresh post-purge organization memberships cannot inherit old rows.
- Admin catalogs include retained revoked/expired history and current effective flags.
  Members can read only effective assignments on their own currently unlocked account.
  Both paths use bounded binary-UUID keyset pagination, fresh MySQL checks, no-store
  responses and no per-row ancestor queries. Group membership never unlocks accounts
  or grants workspace access by itself; no internal entitlement API is added here.
- Mutation, actor audit, membership version, organization authorization version and
  two outbox envelopes commit atomically. Membership events carry IDs, validity and
  both version scopes, excluding roles and names. Organization-scoped invalidation
  events advance Redis/Caffeine version floors after commit and through Kafka.
  Cache failure cannot authorize anything; all membership reads remain MySQL guarded.
  Account and organization retention purge erases these assignments with their anchor.
  Downstream projections must bound cached validity by validUntil and reject stale
  versions; no downstream workspace/content consumer is implemented by this slice.

#### Group join request approval decisions

- V14 introduces PENDING, APPROVED, REJECTED and CANCELLED requests anchored to
  the exact group/account/organization membership. A current unlocked organization
  member may request a currently discoverable APPROVAL group and suggest a custom role; requesting
  never creates membership, changes authorization versions or unlocks accounts.
  Member discovery is governed by the V15 rules described below. The organization-administrator catalog remains separate.
- One pending request per group/organization membership is allowed. Submission UUIDs
  are scoped to organization/requesting account; normalized matching retries return
  the current decision, while changed payloads or retired anchors conflict. A current
  ACTIVE assignment (including an expired assignment not yet revoked) conflicts.
  Requesters may cancel only their own PENDING request. Cancellation and rejection
  permit a fresh request; neither can cancel an approved membership.
- A different human with current organization OWNER/ADMIN or explicitly delegated effective group administration and LOGIN/PASSWORD grant
  must review. Self-review through another linked root is also prohibited. Approval
  requires an explicit role, start and optional end supplied by the reviewer; the
  requested role is never automatically granted. Current group ancestry, account,
  exact organization membership and policy are rechecked. Disabled/revoked targets
  cannot be approved; administrators may reject stale or disabled-group requests.
- Approval creates an ADMIN_APPROVAL membership with a canonical request UUID as
  its string sourceReference. MySQL stores this UUID in source_request_id BINARY(16)
  and a composite foreign key prevents cross-group/account/anchor references.
  The request decision, membership, audits, membership and organization versions,
  and outbox events commit atomically under ordered group fences and organization
  root locks. Only approval changes entitlements and invalidates caches after commit.
- Terminal review retries require the original reviewer account and normalized
  decision fingerprint. They return the historical decision and never recreate a
  revoked membership. Changed decisions conflict. Concurrent cancellation/review
  cannot both win. Submission/cancellation/review never call remote services while
  holding database locks. Audit/outbox payloads omit requested roles and reasons.
- Member queues show only the chosen unlocked account's current organization anchor.
  Administrator queues are scoped to an organization/group and support status filters.
  Both use bounded UUID cursor pagination, fresh authority checks and no-store.
  Requests and decisions are the durable in-app status channel; generalized delivery
  belongs to the future Notification Service. Reasons/review text are erased by the
  configured account/organization retention purge alongside anchored assignments.
  Purge and a new organization membership never revive a historical request.

### Phase 8 — Authorization Projection

Implement:

```text
Caffeine -> Redis -> IAM endpoint -> IAM MySQL
```

with:

- versioned state
- TTLs
- cache invalidation
- fail-closed sensitive checks
- Redis outage behavior
- thundering-herd protection

#### Organization snapshot implementation decisions (first projection slice)

- IAM organization detail reads obtain account/organization-scoped snapshots through
  Caffeine, Redis and MySQL. This does not expose an internal service authorization
  endpoint or implement domain-service caches. Create/list keep their MySQL paths.
- Every detail response requires a fresh, locked MySQL visibility check in the
  existing session transaction: current session/grant, organization/membership status,
  authentication policy, membership ID, role and both versions must match. Cached
  state cannot authorize access. Redis failure/corruption falls back to MySQL; inability
  to establish current permission fails closed. No negative entries are cached.
- Cache lookup occurs before the session transaction; only a successfully committed
  MySQL fallback result is populated afterward. Redis/Kafka calls never hold database
  locks. Hits avoid loading the full organization row but retain current SQL guards.
- Shared snapshots expire with 20–30 second TTL jitter. Existing organization
  authorization_version and membership version fields require no new migration.
  Future metadata/policy/membership mutations must advance the relevant versions
  transactionally and emit invalidation events; cached roles must match current SQL.
- Redis Lua atomically checks snapshot versions and a ten-minute organization version
  floor. Decimal-string comparison preserves exact positive Java long versions above
  2^53. Related keys share an organization hash tag; production Redis Cluster requires
  a cluster-aware client. Caffeine remains bounded and empty on startup. Local version
  floors are bounded to 10,000 organizations with ten-minute access expiry.
- Kafka organization creation/membership activation headers advance version floors
  and evict older local snapshots. Each IAM instance has a distinct consumer group
  starting at latest offsets: invalidations must broadcast rather than compete across
  pods. Duplicate/stale events are idempotent monotonic cache effects without business
  side effects or an inbox table. Malformed headers are rejected with bounded metrics.
  During Redis failure, local invalidation proceeds and the fresh MySQL guard remains
  mandatory; disposable cache effects do not need durable notification processing.
- Standalone cache/listener flags default off; Compose enables both. Metrics use
  bounded outcomes without account IDs, organization IDs, credentials or payloads.
  Full organization revocation, internal service authentication/authorization, group
  projection and request coalescing remain separate complete slices.

### Phase 9 — Outbox / Kafka

Implement:

- transactional OutboxEvent
- batch claiming
- retries/backoff
- Kafka publishing
- idempotent consumers
- authorization invalidation events

#### Outbox publisher implementation decisions (delivery slice)

- Existing organization/invitation/account mutations keep inserting immutable JSON
  outbox envelopes in their MySQL transactions. V9 adds nullable claim-token/lease
  columns and a bounded machine-readable last-error field without changing earlier
  migrations. Rows remain PENDING during reservation and become PUBLISHED only after
  a Kafka acknowledgement. Published rows have no claim; retention is deferred.
- Workers claim at most 100 rows (default 20), ordered by availability/time/ID, with
  `FOR UPDATE SKIP LOCKED` in a short independent transaction. MySQL UTC time governs
  due dates and lease ownership across pods. A random UUID fences each reservation
  batch. Claims renew immediately before sending; expired reservations are skipped.
  Renewal, completion and retry writes require the current token and unexpired lease.
  Each reservation increments attempts with saturation at the integer maximum.
- Network I/O is forbidden inside a caller DB transaction. Each send waits for the
  Kafka acknowledgement with a bounded timeout (20 seconds default) and then marks
  publication in a separate transaction. Process loss, interruption and DB failures
  leave leases for recovery. Acknowledgement followed by lost DB completion can
  deliver duplicates with the same event ID; delivery is at least once.
- Failures reschedule PENDING rows with exponential delay capped at five minutes,
  starting at one second. No security event is automatically discarded. Durable
  diagnostics use only `KAFKA_PUBLISH_FAILED`; logs and record diagnostics exclude
  payloads and exception messages. The Kafka producer error listener is deliberately
  replaced because the default listener can include record data.
- `iam.domain-events.v1` is the default shared IAM event topic. The Kafka key is
  `aggregateType:aggregateId`; the immutable JSON payload retains its existing
  `aggregateVersion` envelope field. Headers include event ID, aggregate type/ID,
  aggregate version (also the canonical `version` header), event type and occurrence
  time. Multiple workers may deliver stale/out-of-order versions. Consumers must
  deduplicate event IDs and compare aggregate versions before side effects; no
  downstream consumer or authorization projection is implemented by this slice.
- Compose explicitly provisions the topic with three partitions and local replication
  factor 1 and enables polling. Standalone publication is opt-in and requires a
  pre-provisioned topic. Production replication/retention/security remain deployment
  concerns. Polling defaults to five seconds, can be disabled independently for tests,
  and exposes bounded delivery/poll-failure counters and indexed oldest-pending age.
  Organization snapshot invalidation is described in Phase 8. Full organization
  revocation remains incomplete until its end-to-end contract is implemented.

### Phase 10 — Hardening

Test:

- concurrent login
- concurrent account unlock
- membership revocation during active session
- credential changes
- refresh replay
- expired grants
- Redis outage
- Kafka outage
- duplicate Kafka events
- stale versions
- signing-key rotation
- brute-force/rate limiting
- service restart/pod loss
- authorization cache races

---

## 25. Non-Negotiable Security Invariants

1. A PendingRegistration is never an authorized UserAccount.
2. Plaintext passwords, PINs, OTPs, and verification tokens are never persisted.
3. AccountGroup linking never grants organization permissions.
4. Preferred account never bypasses account authentication.
5. SessionAccountGrant alone never proves organization/workspace authorization.
6. Revoked OrganizationMembership immediately becomes invalid for authorization even if caches are stale.
7. JWT does not become the source of truth for mutable permissions.
8. Redis/Caffeine/Elasticsearch are never the sole source of authorization truth.
9. Search must not leak revoked/inaccessible resources.
10. Services never read/write another service's database.
11. Security events that require asynchronous propagation use transactional outbox.
12. Cross-service user identity is never trusted from an arbitrary client-controlled header.
13. Resource step-up authentication is additional verification, never permission by itself.
14. Favorites, recents, search hits, cached metadata, or notifications never grant access.
15. A pod/JVM restart must not lose required security state.

---

## 26. Implementation Principle

### Account removal and recovery

Account removal requires explicit account selection when more than one linked account exists and fresh password verification. A personal account is soft deleted; an organization account instead creates a removal request reviewed by another current administrator. Administrators may remove or temporarily blacklist a member within their organization. These actions cover that human's memberships in that organization, including memberships reached through a personal account, without disabling their personal account. An ADMIN cannot remove an OWNER, and the last available OWNER cannot be removed.

Removed accounts retain their data for a configured 3 or 12 calendar months; the deadline is fixed at removal. Personal recovery requires its retained password, and organization recovery requires a current administrator. Recovery is refused at or after the deadline. Temporary blacklist expiry restores only memberships suspended by that action. Recovery and expiry never revive sessions or account grants.

Purged account and membership tombstones do not reserve a current organization account slot or confer historical roles. A fresh approved invitation may create new IDs after purge; this never restores deleted data. Shared preferences are erased when no retained account remains, and revoked refresh proofs are erased with their account.

IAM automatically purges its retained credentials and account-specific personal data at the deadline and emits versioned purge events for owning services. Other services must implement these events to purge their own content; IAM never accesses their databases. Minimal account/membership identifiers and security audit history remain as tombstones for referential integrity. Shared human profile data is erased only when all of that human's accounts are purged.

Membership revocation, account availability, credential versions, session grants, fallback preference, security notices, audit, and outbox records change transactionally. Organization authorization versions invalidate cached projections. Fresh MySQL checks remain mandatory even with stale caches. New invitations cannot bypass an active removal or blacklist restriction. Cross-human mutations acquire account-group fences in UUID order before sessions, credentials, and organization rows.

IAM stores durable security notices and exposes an authenticated inbox. SMTP delivery is retried outside database transactions; destructive actions require configured delivery and a verified contact. The general Notification Service remains responsible for general notifications. Removal notices include the recovery deadline; blacklist notices include the expiry and administrator's reason.

Prefer the simplest implementation that preserves these invariants.

Do not prematurely add:
- per-file ACL rows for inherited workspace access
- directory closure tables unless real subtree-query requirements justify them
- physical DB sharding before operational scale requires it
- separate microservices for every internal component
- permission-heavy JWTs

Design schemas and APIs so these capabilities can be introduced later without changing the fundamental domain semantics.


## Registration and admission update — 8 October 2026

Personal registration and student email challenges use six-digit random codes, salted BCrypt hashes, a five-minute server deadline and at most five attempts. Verification remains distinct from transactional provisioning; unverified pending registrations have no authorization. The existing request field `token` remains compatible with clients and carries the code. SMTP delivers HTML plus plain text; local Compose uses Mailpit, with a loopback-only inbox. Production SMTP retains TLS defaults.

Student admission is a separate institute-scoped workflow after establishing a verified personal identity. A student supplies an institute email at an explicitly configured student-email domain, or their verified personal email plus a JPEG/PNG/PDF student ID or enrollment document (5 MiB limit). Both paths verify mailbox ownership with a new five-minute code. Institute-email admission automatically provisions a UNIVERSITY account after proof; domain configuration is trusted institutional administrator input, not a domain suffix guessed from the user. Evidence admission remains PENDING_REVIEW and grants no institute membership until an institute-scoped curator approves authenticity. Enrollment remains separately confirmed by trusted data; admission alone grants no courses.

An OWNER/ADMIN of the selected UNIVERSITY may delegate an institute-curator capability to an existing current membership anchor for a campus volunteer. It permits admission review, department/course catalog creation and configuration, and academic enrollment curation for that institute. It does not grant general organization administration, other-institute authority, arbitrary private-group creation or personal-account access. Current organization membership/grant/policy still gate every action. Existing OWNER/ADMIN powers are unchanged; institution accreditation and verification of the administrator's right to represent an institution remain an operational prerequisite, not an implemented automated accreditation system.

Student evidence is private S3-compatible object data owned by the admission capability; MySQL stores only admission metadata. Local Compose adds a private RustFS service for this purpose, without host ports. Evidence downloads require current curator authority and are attachments with no-store/nosniff headers. Evidence deletion is queued transactionally after review/expiry/account purge and retried outside DB transactions. Upload alone does not verify authenticity. Orphan objects from an interrupted upload must additionally be expired by a production bucket lifecycle policy. Normal Drive documents remain the Document service's responsibility.

General organization employees are administrator-provisioned and do not require email verification. This is an explicit exception to the personal pending-registration flow, and replaces email invitations as the required employee onboarding path. A generated temporary username/password is returned once to the current organization OWNER/ADMIN over the no-store API; plaintext credentials are never persisted, logged or placed in audit/outbox. No fabricated verified contact is created. Temporary credentials remain valid until first use (no time expiry, per product policy). Login identities remain DISABLED until the first successful employee login replaces the temporary password; no session/grant/token is issued beforehand. Five failed temporary-password attempts require administrator reissue. Reissue changes credential version and revokes existing account grants. Existing usernames remain login selectors after activation; the password is no longer temporary. No personal account or existing human identity is linked automatically. Employee security notices use the durable authenticated inbox when no verified email exists.

Existing verified-email invitation endpoints remain available for legacy explicit invitations and administrative memberships; the new employee workflow is the non-email provisioning route. Student admission does not implement course archives, student-only restrictions on every legacy administrative invitation, document permissions or scheduled offboarding; those are distinct previously identified slices.


## Password recovery and local graph extraction — 8 October 2026

Personal and current UNIVERSITY password credentials support unauthenticated email recovery through
purpose-bound six-digit, salted-hash OTPs valid for five minutes and at most five attempts. The
request endpoint returns an indistinguishable 202, including unknown/ineligible accounts, throttling
and SMTP unavailability. Personal email is the default selector; a student explicitly supplies their
UNIVERSITY account ID and current official email. Pending registrations and COMPANY/CUSTOM employee
accounts are excluded. Resends are limited durably to one per minute and five per hour. Codes are
one-use, bound to credential identity/version and superseded by a newer challenge. Terminal hashes
are scrubbed; account purge deletes recovery data. Email delivery occurs outside transactions through
a bounded transient executor, with retry by a new user request after cooldown if process loss prevents
delivery. Mailpit captures development messages; no code is returned to the API caller.

Organization employees request recovery through a durable organization administrator inbox rather
than email OTP. A valid request alone changes no credential, membership, permission or session.
General organization accounts created through older invitation flows may use their canonical account
UUID as username; initialization adds only recovery metadata and preserves their existing identity.
One open request per account and a ten-minute cooldown bound request spam. A current OWNER/ADMIN
with a live LOGIN/PASSWORD grant independently verifies the employee and issues a six-digit PIN
through a no-store API. The administrator receives plaintext only once and delivers it through a
trusted organization channel. The PIN remains valid until used, with no time expiry per explicit
product policy. Five failures lock the PIN until reissue; reissue/credential-version changes invalidate
older proofs. The temporary PIN is separate from login and account-unlock credentials. Issuance
scrambles/disables the old login credential and revokes sessions/refresh/grants. A successful PIN
exchange installs a permanent password but issues no session, grant or JWT and restores no membership.

Administrator recovery and the earlier temporary-password reset API prohibit self-approval at human
identity level, even through linked accounts. An ADMIN may not reset an OWNER's credentials; OWNER
may reset another eligible OWNER. This narrows the prior generic employee reset authority to prevent
role takeover. Current organization membership/policy/restriction checks remain mandatory. Both administrator reset APIs additionally require the current password of the acting administrator account; a live grant alone is insufficient. Password comparison runs outside database transactions, followed by a locked identity/hash/credential-version recheck inside the account-group fence. Incorrect proofs share the existing durable credential-proof limit of five failures and a fifteen-minute lock, with failures committed before returning denial. Request DTOs redact passwords.
Durable
administrator request notices and employee issuance notices contain no PIN or password. Their existing
SMTP dispatcher operates outside transactions for recipients with verified contacts.

Password replacement, credential version increments, affected session/refresh/grant revocation, audit
and outbox insertion are atomic under current account-group fences. Sessions authenticated by the
changed account are revoked in full; other sessions lose only that account's grants, with safe current
fallback. Credential reset never grants linked-account or organization authority. Email credential
change events use LOGIN_IDENTITY and its credential version; employee request events use their own
request aggregate, while employee issuance/completion advance organization authorization versions.
These namespaces must not be conflated with UserAccount lifecycle versions.

Graphify maintenance uses the project-local workflow configured in .graphify-local.json and the
scripts/graphify-local.ps1 prepare/finalize commands. Extraction calls no separate Gemini/provider API;
AST extraction is local and semantic documentation extraction uses the existing Codex host agent.
This is not a promise of an offline Codex model. Source snapshot validation and complete semantic
coverage are required before graph/report/HTML/manifest publication and pending-marker removal.


## Auth security plan Phase 3 - Login attack protection (8 October 2026)

Login admission is enabled by default and uses expiring Redis state before password
verification, employee activation, and session creation. All three login routes are
covered: personal email, organization account UUID and employee username. Known
selectors resolve to the same account UUID; unknown selectors are still protected.
Email normalization happens before login DTO validation. Passwords remain verbatim.
The cheap identity lookup precedes admission to resolve aliases; endpoint-wide request
limiting is a separate Phase 4 concern.

The socket peer is the source identity. Forwarded, X-Forwarded-For and X-Real-IP are
not trusted, and server.forward-headers-strategy remains none. Behind a proxy, source
counters therefore represent that proxy until a separately reviewed trusted-proxy
configuration exists. Direct application calls without a peer use an internal bucket.

Atomic Lua reserves one in-flight attempt in each IP, account and IP/account hash.
Defaults are 50, 10 and 5 respectively, over a fixed 15-minute window. Effective
pressure is failures minus the cleared sequence floor plus in-flight reservations.
The limit is checked atomically for all dimensions before password work, including
concurrent attempts. The first reservation sets the expiry; failed or blocked attempts
do not slide the window. Completion removes the reservation and advances a monotonic
failure sequence when authentication fails. Success advances account/pair cleared
floors only through the captured admission sequence, preserving later failures and
all source-IP failure history. Generation nonces prevent a late completion from
modifying expired/recreated state. Abandoned reservations expire with the window.

Redis key prefix auth:login:v1 and hash tag {login} are followed by SHA-256 source,
account-selector or pair digests. No raw email, username, peer address or secret is
stored in these keys. These are pseudonymous temporary identifiers, not an assertion
of resistance to dictionary recovery. Related keys share one cluster hash slot for
atomic execution; the client must still be cluster-aware in a clustered deployment.
This concentrates login admission in one slot and requires capacity planning.

Redis admission exceptions, malformed state or missing results fail closed with the
same generic 401 as incorrect credentials. No credential/session mutation follows a
failed admission. Redis I/O occurs outside MySQL transactions. If bookkeeping fails
after a successful committed login, return its valid response and increment a bounded
completion_unavailable metric instead of orphaning the session; its reservation will
expire. Outage while recording failure preserves the original generic failure.

Shared Compose Redis uses noeviction rather than allkeys-lru so memory pressure cannot
silently evict attack counters. The existing server is reconfigured in place for local
tests; no infrastructure container is replaced. Exhaustion denies new admissions and
cache writes; authorization caches continue their existing authoritative MySQL fallback.
Redis remains disposable: restart/operator deletion can reset temporary signals, and
these counters do not permanently label or lock any account. Production availability,
capacity and gateway abuse controls remain deployment responsibilities.

Pending employee temporary credentials retain the explicit durable five-failure rule
requiring administrator reissue. This credential-specific rule is an intentional
exception to automatic throttle expiry. Activated employees receive expiring protection;
no User/LoginIdentity availability flag is changed by the new admission mechanism.
Recovery PIN and linked-account challenge policies are unchanged.

Configuration is auth.login-protection.enabled/key-prefix/window/ip-limit/account-limit/
pair-limit, with matching LOGIN_ATTACK_PROTECTION_* environment overrides. Tests may
explicitly disable admission in existing unrelated MySQL suites; new security tests
exercise it enabled against isolated keys and Redis database 15. A reusable Redis-only
test base accepts external Compose host/port settings and retains a labeled reusable
Testcontainers fallback when those settings are absent. No shared Redis flush is used.

## Auth security plan Phase 4 - Endpoint rate limiting (8 October 2026)

Endpoint request admission is enabled by default, before Spring Security and controller/body
processing, after request correlation. Redis atomically counts all admitted attempts per socket
peer and endpoint policy in a fixed one-minute window. Defaults are registration 10, login 60,
refresh 120, forgot-password 10, reset-password 20 and verification/completion 20. Employee
and account-specific login aliases share the login bucket; employee recovery aliases share
their corresponding recovery policy. Student admission creation and verification use the
registration and verification policies. UUID/path variations cannot create fresh buckets.
There is no email resend endpoint; existing recovery requests remain subject to their durable
cooldowns in addition to these request limits. No credential or authorization semantics change.

Keys use auth:rate:v1:<POLICY>:<SHA-256 socket peer>; no raw identifier, IP or secret is stored.
Each atomic operation uses one key, allowing independent Redis cluster slots. The initial
request establishes TTL; blocked requests do not increment or extend it. Exhaustion returns
429 with rounded-up Retry-After seconds and a no-store correlated problem response. Redis
errors, malformed state or missing/non-expiring state fail closed with a generic 503 before
controller execution. Public health/JWKS and unrelated authenticated routes are unaffected.
Forgot-password throttling depends only on source/policy, preserving account enumeration
resistance and the existing indistinguishable 202 for admitted requests.

Configuration is auth.rate-limit.enabled/key-prefix/window and registration-limit/login-limit/
refresh-limit/forgot-password-limit/reset-password-limit/verification-limit, with matching
AUTH_RATE_LIMIT_* environment overrides. Window bounds are one second to 24 hours; limits
must be positive and bounded. Metrics auth.rate_limit use bounded policy/outcome tags only.
Forwarded headers remain ignored (server.forward-headers-strategy=none). Deployments behind
proxies currently share the proxy's source bucket; a trusted-proxy design remains separate
work. Production Redis must preserve counters with noeviction and adequate capacity. Redis
restart/deletion can reset disposable limits, and upstream connection/body-size protection
remains an infrastructure responsibility. Existing Phase 3 login failure state is independent.

## Auth security plan Phase 5 - Refresh transport and all-device logout (8 October 2026)

The existing refresh design is retained: opaque UUID plus 256 random secret bits, only
SHA-256 hashes in MySQL, atomic single-use rotation, constant-time secret comparison and
session/family revocation on proven consumed-token replay. A wrong secret never revokes a
legitimate session. There is no concurrency/retry grace period; browser clients must serialize
refreshes and authenticate again after losing a rotated response. Access-token lifetime
remains five minutes; absolute session/refresh lifetime remains 12 hours and grant deadlines
remain authoritative. Revocation audits commit with the mutation. Existing local IAM session
checks are current MySQL checks; offline downstream JWT validation alone cannot promise
instant session revocation. Session event outbox propagation remains the previously deferred
resource/projection integration boundary, not a new guarantee from this slice.

Browser transport is an explicit opt-in on existing personal, account-specific and employee
login, refresh, logout and logout-all endpoints: X-Auth-Transport: cookie plus an exact
allowlisted Origin. auth.browser-refresh.allowed-origins (AUTH_BROWSER_REFRESH_ALLOWED_ORIGINS)
is empty by default and permits only explicit HTTPS origins without wildcards, userinfo,
paths, queries or fragments. Compose forwards this setting. Restricted credentialed POST
CORS on /api/v1/auth/** allows only configured origins and Content-Type, Authorization,
X-Auth-Transport headers. Browser-origin checks precede every credential/session mutation;
Missing/null/untrusted/duplicate origins in browser mode, or unknown/duplicate transport headers, fail with 403. This custom-header
and exact-origin requirement supplies browser CSRF protection for cookie refresh; unrelated
access APIs continue to require explicit bearer JWTs and never authenticate from cookies.

Browser login/refresh places the refresh secret only in __Host-auth-refresh, with Secure,
HttpOnly, SameSite=Strict, Path=/ and no Domain or persistent Max-Age. MySQL enforces the
absolute deadline; rotation does not prolong the session. JSON browser responses contain
refreshToken=null. Refresh in browser mode accepts exactly one valid named cookie and no
JSON refresh body. Missing/duplicate/malformed cookies and ambiguous input fail with generic
401 before rotation. Authentication failures clear the browser cookie; origin denials do not.
Cookie-only refresh without the explicit mode is rejected. Without the mode header, existing
native/API JSON request/response behavior remains unchanged and ambient cookies are ignored.
HTTP logout still requires a bearer JWT and clears the browser cookie when explicitly selected.
Clients must use HTTPS and a same-site frontend/auth deployment for Strict cookies; this slice
does not add development insecure-cookie overrides or trust forwarding headers.

POST /api/v1/auth/logout-all requires a current server-authoritative session context and at
least one live linked-account grant, including a legitimate fallback grant. It accepts no
target group/account/user IDs. Under the existing account-group fence it revokes every active
session, all refresh credentials and active account grants in that current AccountGroup in
one MySQL transaction, using bulk SQL rather than loading historical sessions. Existing LOGOUT
grant reason is reused. Each newly revoked session receives SESSION_REVOKED audit evidence;
the operation records ALL_SESSIONS_REVOKED. V20 extends the audit constraint and domain enum.
Revoked/expired/wrong-subject/unusable callers cannot revoke another device. Unlinked groups
and other humans are unaffected. Login/refresh serialize on the group fence: sessions committed
before logout-all are revoked; fresh authentication after its commit can create a new session.

#### Versioned single-session logout audit decision

- Explicit single-session logout preserves SESSION_REVOKED and adds a typed schema-1
  auth.logout.completed envelope. The subject must match the locked session's
  login account before revocation; that verified account is the actor and the
  session is the target, including when its login identity is no longer available.
- The audit envelope and identical SECURITY_AUDIT outbox fact commit with session,
  grant and refresh revocation. Audit persistence failure rolls back all changes.
  Already revoked sessions emit no additional fact. Correlation/privacy, restricted
  routing and retained retry policies follow the versioned login audit decision.
- V22 permits logout envelopes while retaining historical null audit envelopes.
  Bulk logout, system revocation and refresh replay retain their existing audit
  semantics and await separate typed envelopes with appropriate actor attribution.

#### Local Elastic Compose deployment decision

- Unified docker-compose.yml keeps telemetry in the existing unidocs-auth
  project alongside the application services. Elasticsearch, Kibana,
  standalone APM Server and Filebeat use the same pinned 9.5.5 release. No telemetry
  service becomes an auth startup/readiness dependency or authoritative audit store.
- Ignored local credentials separate bootstrap, Kibana system, collector publishing
  and APM intake. Elasticsearch/APM remain private; only Kibana publishes loopback.
  Local HTTP is limited to the Docker network; production requires TLS and reviewed
  separate setup/publish/query roles, retention and backups.
- Filebeat collects auth ECS stdout via read-only daemon logs, without a Docker
  socket. Persistent bounded registry/queue state and a seven-day local log lifecycle
  use Filebeat-managed data streams. APM assets use the supported Kibana package API
  and integration-owned data streams. No document-service search index is added.
- The local APM publisher receives explicit restricted-index read only on
  .apm-agent-configuration for the receiver's configuration cache; no unrestricted
  system-index privileges are granted. Local synthetic log and trace delivery and
  OTLP authentication are verified independently of the stopped auth container.

#### Isolated real HTTP telemetry acceptance decision

- Opt-in Compose acceptance uses a real random-port auth test application and the
  existing auth_service_test schema, without redeploying or touching application
  data. Scoped Filebeat/APM read credentials query only diagnostic projections.
- Test stdout is explicitly mirrored into the existing runner's Docker log stream;
  pipefail preserves Maven failures. Real failed-login HTTP context must correlate
  with indexed diagnostic logs and an APM transaction, while credentials, export
  secrets and spoofed identity headers remain absent. Normal tests skip this optional
  acceptance when Elastic environment variables are absent.

HTTP request tracing exports only the canonical bounded `http.request.method` attribute (standard methods or `_OTHER`), allowing APM to classify request transactions without exporting raw URLs, queries, headers or identity.


#### Local telemetry outage acceptance decision

The opt-in Compose outage test deliberately stops only the four optional telemetry
services and restores their existing containers in a finally block without recreation.
An isolated real HTTP application must continue login, authenticated access, denial,
logout and readiness while its enabled OTLP exporter fails. MySQL audit/outbox facts
remain authoritative and privacy checks remain mandatory during telemetry failure.
The test uses auth_service_test and preserves business containers and application data.
Prolonged storage/queue exhaustion and production recovery remain separate work.

Validation: the isolated real HTTP outage test passed with all four telemetry services stopped and actual OTLP export failing.


#### Versioned proven refresh replay audit decision

Only a secret-hash match on an already consumed refresh token establishes replay.
That existing branch records schema-version-1 auth.token.refresh.failed with FAILURE,
reason REFRESH_REPLAY, UNKNOWN actor and the locked session as target. A replaying
holder is not a verified account actor; existing audit row owner IDs remain affected
owner references. The immutable envelope and SECURITY_AUDIT outbox commit in the
existing session/grant/refresh-family revocation transaction, before generic 401.
Audit/outbox failure rolls back revocation and fails the request. Wrong secrets and
unproven failures do not produce this fact or change the existing revocation semantics.
V23 extends envelope constraints without changing historical null or login/logout facts.
Repeated replay remains governed by the existing behavior, without a retry grace period.

#### Versioned all-device logout action audit decision

Explicit logout-all retains ALL_SESSIONS_REVOKED and records schema-version-1
auth.logout.completed with SUCCESS outcome and LOGOUT_ALL reason. The verified
requesting login account is the actor; the locked current AccountGroup is the target,
with explicit accountGroupId and requesting sessionId. The operation accepts no
client target IDs and AccountGroup still confers no authorization grant.
The action envelope and immutable event ID enter SECURITY_AUDIT outbox in the same
bulk revocation transaction. Audit/outbox failure rolls back session, grant and
refresh revocation. Existing per-session legacy SESSION_REVOKED rows, LOGOUT grant
reason, group fencing, current-authority validation and other-human isolation remain.
V24 extends envelope consistency checks while preserving prior and null envelopes.
System revocation and per-session bulk envelopes remain separate audit slices.


#### Local Prometheus scrape deployment decision

The optional metrics deployment co-locates pinned Prometheus with auth in its Docker
network namespace. It scrapes only authenticated loopback management port 9091, using
an ignored protected credentials file, and exposes only its local UI through host
loopback port 9090. The management listener remains unpublished. Auth has no Prometheus
startup or readiness dependency. Metrics retain seven days/512MB in a reusable volume.
An intentional app rebuild/configuration update is needed for the first deployment;
replacement of the app namespace requires Prometheus reattachment without data loss.
The six existing rules plus target-down and failed-login-spike rules are validated by
the deployed promtool and evaluated locally; notification routing and dashboards remain
separate. Production tuning, remote TLS/RBAC, backups and recovery remain pending.

#### Versioned generic refresh rejection audit decision

Malformed tokens and ordinary service-level refresh rejections record REFRESH_FAILED
with schema-version-1 auth.token.refresh.failed, FAILURE and INVALID_REFRESH.
Actor is UNKNOWN; actor, target and session identifiers are absent, even when an
untrusted token selector resolves a stored session. No credentials or selectors enter
these facts. Proven replay keeps its separate REFRESH_REPLAY fact without duplication.
The mandatory audit and identical SECURITY_AUDIT outbox commit before generic 401;
any existing no-usable-account revocation shares that transaction and rolls back on
audit failure. Infrastructure failures and API/filter validation rejections remain
outside this slice. V25 preserves legacy facts and constrains the new envelope.

#### Local Grafana dashboard deployment decision

Unified docker-compose.yml includes pinned Grafana 13.2.2 to unidocs-auth with a
loopback-only UI, disabled anonymous access/sign-up and a generated protected
admin credential file. Reusable SQLite storage and rotated logs survive restarts.
The provisioned read-only Prometheus datasource queries auth-service:9090 through
Grafana's server proxy; no private scrape credential is given to Grafana/browser.
Fourteen provisioned panels use the existing bounded series and selected environment.
Grafana starts independently; no auth readiness/startup dependency is introduced.
The dedicated startup script reuses compatible containers and never updates auth.
This local dashboard baseline does not establish production RBAC/TLS, alert delivery
or backup/recovery. Live data requires the separate metrics deployment to be running.
Local acceptance verified file provisioning, exact panel query contracts and anonymous rejection without starting auth or Prometheus.

#### Local collector recovery acceptance decision

An opt-in standalone recovery harness reuses existing Elasticsearch, Filebeat and
test-runner containers without starting the application or changing transactional
schemas. Three uniquely identified credential-free synthetic ECS records exercise
normal ingestion, Docker-log catch-up after collector downtime and continued ingestion
after a second restart with persistent registry state. Queries use the existing scoped
collector identity inside the runner; secrets never enter command arguments or stdout.
At-least-once delivery is accepted; duplicate diagnostic copies do not fail acceptance.
Filebeat is restarted in finally after deliberate interruption, including assertion
failure. A harness lock prevents duplicate recovery runs; run no other telemetry outage
acceptance concurrently. This checks retained local log delivery, not real HTTP/auth
semantics, log rotation/deletion, disk/queue exhaustion or production recovery guarantees.
Live acceptance remains pending until Docker access is available.

#### Versioned email password-reset completion audit decision

Successful verified-email password recovery retains PASSWORD_RESET_COMPLETED and
records schema-version-1 auth.password.reset.completed with SUCCESS outcome and
EMAIL_RECOVERY_VERIFIED reason. The locked affected account is the ACCOUNT target;
the actor remains UNKNOWN, with no actor/session/tenant assertions from recovery
credential possession. Owner columns retain affected-owner references only.
The identical envelope/event ID enters SECURITY_AUDIT outbox in the credential-change
transaction with proof consumption, credential-version increment and security revocation.
Persistence failure rolls back the operation. No password, code, email selector or
unvalidated identity/network metadata enters the envelope. Existing lifecycle outbox
and generic reset API behavior remain unchanged. V26 preserves historical null and
prior envelopes while constraining reset target/actor consistency. Unproven failures,
recovery requests and employee recovery remain separate audit slices.
Validation: all 58 targeted tests passed. V26 applied to auth_service_test and all 26 Flyway migrations validated. Audit/outbox failure tests verified atomic rollback and successful retry of the same proof.


## Local administrator development exception — 10 October 2026

At the user's explicit request, the local `unidocs-auth` Compose stack is reset
with fresh data, credentials and generated cryptographic material, and uses
administrator service access during development. This deliberately supersedes
the earlier local least-privilege database and telemetry configuration:

- Auth connects to MySQL as `admin`.
- The optional TLS Keycloak database identity receives global administrator
  privileges. The default HTTP development Keycloak uses its embedded database.
- The Elasticsearch `admin` identity receives `superuser` access.
  Kibana retains the supported reserved `kibana_system` identity.
- Test database schema/user isolation remains in place.

Deployment remains in one `docker-compose.yml`, with literal published ports bound
to `127.0.0.1`. One ignored `.env` is authoritative for all local settings and
credentials. Signing keys, TLS material and derived file adapters remain together
in ignored `.secrets/`; adapters must not be edited independently. Ordinary starts
preserve these files and reusable volumes; destructive resets require explicit
user authorization. Runtime access grants, account/session semantics, secret
redaction and the prohibition on plaintext user credential persistence are
unchanged. This is a local-development exception, not a production architecture:
production must restore least-privilege database, setup, publishing and query
identities before deployment.

Local configurable administrator logins use `admin` / `admin123`. RustFS requires an eight-character secret and uses `admin` / `admin1234`. Reserved MySQL `root`, Elasticsearch `elastic` and Kibana `kibana_system` identities retain their names with password `admin123`; isolated test identities and cryptographic keys/tokens remain distinct.

The local shared `unidocs_private_network` uses a bridge with outbound internet access (`internal: false`) so Kibana Fleet can reach the Elastic package registry. Published host ports remain bound to 127.0.0.1. Existing internal networks must be recreated to apply this network-level change; retain volumes.

Local persistent Compose volumes have fixed explicit names independent of the Compose project name. Existing assigned names are preserved. Mailpit uses mailpit-data with MP_DATABASE=/data/mailpit.db to retain development messages across recreation. Development Keycloak retains its existing bind directory; HTTPS Keycloak stores state in MySQL. Redis remains a disposable nonpersistent authorization cache; stateless services and initialization jobs require no data volumes.

Local Keycloak advertises https://localhost:8443 as its frontend hostname to make browser redirects and third-party check iframes reachable from the host. Auth validates the matching issuer https://localhost:8443/realms/unidocs-services, while fetching trusted JWKS through https://keycloak:8443/realms/unidocs-services/protocol/openid-connect/certs on Docker. This supersedes the earlier Docker-only advertised issuer; issuer identity need not match the JWKS transport hostname. TLS trust and audience/subject/scope checks remain enforced.


## Integrated deployment profiles — 14 October 2026

The existing integrated Compose entry point exposes exactly dev, offline and prod. Auth and Document keep their existing service names across profiles. Auth scripts/compose.ps1 selects both Compose services and Spring/runtime settings; a plain Compose profile flag does not supply all application mode settings. Main .env owns COMPOSE_PROFILES and APPLICATION_LOG_LEVEL; service credentials remain in each existing single ignored .env.

Offline selects only Auth/Document diagnostic startup with Swagger and no infrastructure-dependent workers/exporters; data-dependent APIs remain unavailable/fail-closed. Development selects configured development infrastructure and allows application DEBUG/INFO control from main .env. Local production mode selects runtime infrastructure/observability, disables Swagger and application console capture, and ships bounded rotated ECS diagnostics through Filebeat alongside supporting-service logs. Auth/Document transport remains strict HTTPS, with separate local application TLS keys and a Document CA bundle retaining system trust. Profile switching preserves credentials, signing keys, service identities and data volumes, and stops inactive project services before startup. See docs/COMPOSE_PROFILES.md for commands and verification limits.


## Explicit deployment profiles — 14 October 2026

This agreed contract supersedes the earlier same-service-name deployment profile section. The sole integrated Compose entry retains existing service includes but each application YAML defines explicit dev/test/offline/prod service variants. Offline variants have no supporting dependencies, credential environment or mounts. Shared core services are common where their configuration is identical. The virus scanner and one Filebeat per host belong to common Compose; prod includes monitoring automatically, while monitor is additive to dev/test. No runtime script selects application configuration; an optional shell helper selects profiles only.

Test services contain their running applications and Maven tooling. Live test application schemas are separate from destructive integration-suite schemas, with existing scoped test principals and isolated Redis/topic/storage state; no privileged database credentials are exposed to applications. Minimum core excludes search/preview deployment dependencies and explicitly disables their features. Production preserves existing identities/signing material, uses strict application HTTPS and external SMTP, rejects missing prerequisites, and sends diagnostics through common observability. All retained data volumes remain unchanged. See docs/COMPOSE_PROFILES.md for topology, configuration ownership and validation.

Shared monitor scraping requires Auth management to be reachable inside the private Docker network in dev/test. This supersedes the earlier universal loopback requirement only when the explicit allow-private-network flag is enabled, dev/test is active, prod is absent, the management port is separate and the configured scrape token passes validation. Default and production listeners remain loopback-only; adding dev to prod cannot bypass that restriction. No application API receives metrics-token authority.
