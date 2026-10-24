# AGENTS.md — Drive Platform / Auth (Codex + Graphify)

## Operating priorities
- Correctness, security, data preservation, and `PROJECT_SPEC.md` take precedence over token savings.
- Implement the smallest complete vertical slice; do not expand scope or change unrelated files.
- Read the **relevant sections** of `PROJECT_SPEC.md` before architectural, domain, security, database, or API decisions. Identify conflicts before changing established semantics.
- Current focus: IAM/Auth. Default order: bootstrap → Flyway/MySQL/Testcontainers → pending registration/verification → User/UserAccount provisioning → login/JWT/JWKS/session → linked-account unlock → organizations → groups → authorization cache → outbox/Kafka → hardening.

## Token- and tool-efficient execution
- Keep user-facing replies under 50 words unless detail is requested. On success, report outcome and test status briefly; on failure, give blocker and next action.
- No routine progress narration, repeated explanations, full logs, full-file dumps, or echoed diffs.
- Search using graphify the smallest relevant paths first; inspect only needed sections. Exclude dependencies, build outputs, caches, generated artifacts, and unrelated services.
- Reuse context already available. Avoid repeated searches, reads, and tests without a reason.
- Use direct patches for routine code edits. Do not write unnecessary Python or other helper scripts to change a single line or make a small Java edit; use scripts only when a repetitive transformation clearly warrants them.
- Prefer one agent. Delegate only clearly independent work when expected benefit outweighs extra context, coordination, and tool cost; never overlap edits.
- Make targeted changes; run relevant tests, including negative-path tests for security-sensitive behavior. Do not skip necessary validation to save tokens.
- Ask questions only for essential ambiguities. Avoid unnecessary planning for straightforward edits.
- If automatic approval review denies an action, stop work on that action and ask the user for permission and direction before proceeding. Do not retry the denied action or use a workaround. Graphify is the explicit exception: preserve its state, record the skip/failure, and continue unrelated authorized task work under the Graphify policy below.

## Agent Budget Control

- Default to a single agent.
- Do not spawn subagents unless explicitly requested.
- Avoid repeating completed research or implementation.
- Preserve all partial implementation on interruption.
- Never bypass mandatory security or validation checks.

## Stack and design
- Java 25; Spring Boot 4.1.1; Maven 3.9.16; Spring Security/Data JPA; MySQL/Flyway; Redis/Caffeine; Kafka; Testcontainers; Actuator/Micrometer/Prometheus; OpenTelemetry where configured.
- Do not replace major technologies without an explicit request.
- Organize Java packages by capability (registration, user, account, authentication, credential, session, organization, group, authorization, audit, outbox, security, shared), not global controller/service/repository buckets.
- Use explicit Java types (not `var`), constructor injection, thin controllers, application-service transactions, immutable DTOs where practical, and validation at boundaries.
- Name classes, files, methods, and variables for the action they perform and the data they act on; use consistent domain terms and avoid vague or misleading names that imply a different responsibility.
- Do not expose JPA entities as REST DTOs; avoid network calls inside database transactions.
- For completed features, include applicable migration, domain, persistence, use case, API/DTO, validation, security, tests, and audit/outbox behavior.

## Persistence and service boundaries
- MySQL is transactional truth; evolve schema via Flyway, not production Hibernate auto-DDL.
- Prefer UUID domain IDs (UUIDv7 for suitable new high-volume records), efficient MySQL storage where appropriate, UTC timestamps, deliberate indexes/constraints, and pagination.
- No cross-service foreign keys or direct access to another service's database. Avoid N+1 queries.
- The Document service owns document metadata; binaries belong in S3. Use a self-referencing Directory, not SubDirectory entities; prevent cycles. Workspace ID is the metadata locality key.
- Direct directory counters should normally be strongly consistent; descendant counters may be eventually consistent via outbox/Kafka. Elasticsearch is a reconstructible search projection, never authority for authorization, hierarchy, membership, exact existence, or sensitive counts.
- Enforce visibility on every search path, including cached metadata, suggestions, favorites, and recent items.

## Non-negotiable IAM/security invariants
- In production and production-like environments, never store plaintext passwords, PINs, OTPs, refresh secrets, or verification tokens; never log secrets or authorization headers. During local development, `user_details.json` is the canonical lookup for synthetic test users. For each synthetic user, maintain their name, email, fixture password, account ID, user ID, IAM role/role ID, IAM ACL assignments (principal, resource, granted role/permission, and current status/context), and session information needed by tests. Update the JSON in the same task whenever a user, credential, role, ACL grant/revocation, or relevant resource assignment is created or changed; remove or mark revoked ACL entries when access is revoked. Never put production or real-user credentials there, and never log passwords, tokens, or authorization headers.
- PendingRegistration grants no authorization. Verification and completion are distinct; provisioning is transactional, retry-safe, and idempotent. Unverified registrations cannot create ordinary sessions, memberships, or documents.
- AccountGroup and preferred account are navigation concepts, not authorization grants.
- The login account receives an initial SessionAccountGrant with `authMethod=LOGIN`; other linked accounts require a valid challenge. Multiple grants may coexist. No global server-side `activeAccountId`.
- A SessionAccountGrant alone does not authorize organization/workspace access. OrganizationMembership revocation kills descendant access; sensitive checks fail closed.
- JWTs are small: `sub`, `sid`, `iss`, `aud`, `iat`, `exp` as applicable; no mutable permission graph. Use asymmetric signing, JWKS/rotation, and local downstream signature/issuer/audience/expiry checks.
- Session, refresh, grant expiry/revocation, and mutable authorization remain server-authoritative. Use stateless access-token processing.
- Use 401 for missing/invalid authentication, 403 for authenticated denial. Never trust client-controlled identity headers. Step-up authentication is not a permission grant.
- Organization revocation must address authorization versioning, outbox/Kafka propagation, Redis/Caffeine invalidation, relevant session grants, durable notification, safe account fallback, and prevention of stale content exposure.

## Authorization caching and events
- Lookup: domain Caffeine → shared IAM Redis → IAM internal endpoint → IAM MySQL.
- IAM alone writes/deletes shared authorization Redis state. Other services may read it and cache locally; new pods start with empty Caffeine; no bulk preload.
- Cache state is disposable; use versions to reject stale state/events; Kafka invalidates local caches.
- For asynchronous security/domain mutations, commit aggregate and outbox event in one MySQL transaction. Publish committed records only; bounded batches/retries; idempotent consumers; tolerate duplicates and out-of-order delivery; no DB transaction held across Kafka/Redis calls.

## Java Commenting Instructions

- Add JavaDoc to public and protected methods.
- Document method purpose, `@param`, `@return`, and `@throws` where applicable.
- Add inline comments only for complex or non-obvious logic.
- Explain **why**, not what the code does.
- Keep comments concise, clear, and meaningful.
- Avoid redundant comments for obvious code.
- Update comments when method behavior changes.
- Never modify code or business logic when adding comments.

## Workspace, Compose, and secrets
- Integrated Compose entry point: `../docker-compose.yaml`; shared includes: `../docker/compose/`; shared support assets: `../docker/supporting_files/`.
- From Auth, use `docker compose -p unidocs -f ../docker-compose.yaml ...` with named services. Inspect existing topology and live containers before changing or creating resources.
- Auth service include: `docker/compose/auth-service.yml`; Auth test tooling belongs to `auth-service-test`. Use `auth-service-test` on host port `8080` whenever a live Auth service is needed for testing. Do not start or use `auth-service-dev`, `auth-service-offline`, `auth-service-prod`, or another Auth process/container unless the user explicitly asks. The sibling Document test service is `doc-service-test` on host port `8081`. Sibling Doc and frontend entry points are already integrated; do not duplicate includes, overlays, networks, or infrastructure.
- Workspace `../.env` owns shared infrastructure settings; Auth's ignored `.env` owns Auth-specific credentials, DB names/options, identities, issuers, audiences, and resource names. Preserve existing values; do not scatter new env files.
- Preserve existing containers, volumes, databases, keys, certificates, truststores, and ignored generated assets. Never clear application data to make tests pass.
- Auth secrets stay in ignored `.secrets/`; use `scripts/prepare-local.ps1` for setup. Do not regenerate signing material or credentials unnecessarily.
- Prefer reuse of Compose project `unidocs`, compatible stopped containers, and `scripts/test-compose.ps1`; use `--no-recreate` when appropriate. Every Auth test, including live test applications and all test suites, must use the existing `auth_service_test` schema. Every Document test must use the existing `document_service_test` schema. Never create or provision another MySQL schema for any test purpose; preserve existing databases and data.
- Do not create duplicate infrastructure with Testcontainers when existing compatible shared services can serve the test. For reusable new containers, use project `unidocs` and meaningful labels; preserve volumes.
- For detailed Compose ownership and environment-variable mappings, inspect existing project configuration rather than copying historical container IDs or assuming current runtime state.

## Testing and observability
- When using the sibling Angular app for UAT, use its standard `ng serve` endpoint on port 4200; do not use Angular SSR or port 4000.
- Mockito for isolated collaborators; direct domain-invariant tests; Testcontainers for infrastructure integration tests when needed. Database-backed tests must reuse the existing service test schema (`auth_service_test` for Auth, `document_service_test` for Document); never create a per-suite, per-runner, or live-test-app schema.
- Reuse existing synthetic development users for tests. For tests needing different authority, use an existing user and modify its access or IAM role accordingly. Create a user only when the scenario requires a distinct identity or lifecycle state; do not create users unnecessarily.
- Before any local development test that depends on an application user, inspect that user's complete `user_details.json` record and verify the required login identity/credential, account and user IDs, session state, IAM role, ACL grants, and relevant resource assignments. Do not guess or reuse stale assumptions; update the JSON when fixture state changes. Keep credential values out of logs and reports. This file is only for synthetic development users, never production or real users.
- Cover relevant positive/negative cases, especially verification expiry/attempts, idempotent provisioning, JWT/refresh replay, session/grant revocation, linked-account unlock, authorization cache/versioning, outages, outbox retries, key rotation, and concurrency.
- Emit structured logs, correlation IDs, metrics, and configured traces for important flows; never expose secrets or full tokens.
- Run affected tests after changes; fix failures before declaring success, or clearly report blockers.


- This is a Java Maven project. Use Java, not Python.
- Never create `.py` files.use existing .py when needed
- Use Maven for building, testing, and dependency management.
- Follow existing Java conventions and project structure.

## Code Editing
- Prefer direct patches for small, targeted changes.
- Never rewrite entire files unnecessarily.
- For repetitive bulk changes, prefer Java-aware refactoring tools such as OpenRewrite.
- Reuse existing refactoring recipes before creating new ones.
- Do not introduce unnecessary scripts, tools, or dependencies.
- Use existing tools for repetitive work instead of generating lengthy scripts.

## Error Resolution
- Analyze Maven errors and fix Java source directly.
- Use `mvn compile` and `mvn test` for verification.
- Apply minimal fixes without modifying unrelated code.
- Avoid repeating successful checks unnecessarily.

## Reporting
- Do not output entire files or lengthy logs unless requested.


## Scope and architectural decisions
- Avoid premature per-file ACLs, directory closure tables, physical sharding, extra microservices, permission-heavy JWTs, duplicate preferred-account truth, and Elasticsearch-backed authorization.
- Prefer the simplest implementation preserving `PROJECT_SPEC.md` invariants. Document durable new architectural decisions in `PROJECT_SPEC.md`.


## Graphify Maintenance
use graphify when you need.