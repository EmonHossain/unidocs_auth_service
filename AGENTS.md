# AGENTS.md — Codex Instructions

## Mission

Implement the Drive Platform according to `PROJECT_SPEC.md`.

Read `PROJECT_SPEC.md` before making architectural, domain, security, database, or API decisions.

If a requested change conflicts with `PROJECT_SPEC.md`, explicitly identify the conflict before changing established semantics.

## Current Priority

Build the IAM/Auth service first.

Work in small, complete vertical slices. Do not implement every future feature at once.

Unless the task explicitly says otherwise, prioritize:

1. project bootstrap
2. Flyway/MySQL/Testcontainers
3. pending registration + verification
4. User/UserAccount provisioning
5. login/JWT/JWKS/session
6. linked-account unlock
7. organizations
8. groups
9. authorization cache
10. outbox/Kafka
11. production hardening

## Technology

Use:

- Java 25
- Spring Boot 4.1.1
- Maven 3.9.16
- Spring Security
- Spring Data JPA
- MySQL
- Flyway
- Redis
- Caffeine
- Kafka
- Testcontainers
- Actuator
- Micrometer/Prometheus
- OpenTelemetry where configured

Do not replace major technologies without an explicit task requesting it.

## Package Structure

Prefer domain/capability-oriented packages:

```text
com.<company>.auth
├── registration/
│   ├── api/
│   ├── application/
│   ├── domain/
│   └── persistence/
├── user/
├── account/
├── authentication/
├── credential/
├── session/
├── organization/
├── group/
├── authorization/
├── audit/
├── outbox/
├── security/
│   ├── jwt/
│   ├── jwks/
│   ├── ratelimit/
│   └── config/
└── shared/
    ├── error/
    ├── validation/
    ├── events/
    └── config/
```

Avoid one giant global `controller/`, `service/`, `repository/`, `entity/` package layout.

## Feature Completion Rule

For each feature, normally implement all relevant layers before calling it complete:

1. Flyway migration
2. domain model
3. persistence mapping/repository
4. application/use-case service
5. REST DTO/controller if externally exposed
6. validation/error handling
7. security checks
8. unit tests
9. integration tests
10. audit/outbox behavior where security/domain propagation requires it

Run tests after changes and fix failures before finishing.

## Database Rules

- MySQL is the transactional source of truth.
- Use Flyway migrations.
- Do not rely on Hibernate schema auto-generation in production.
- Prefer UUID domain identifiers; UUIDv7 is preferred for new high-volume records when supported cleanly.
- Store UUIDs efficiently in MySQL (for example BINARY(16)) when the persistence design supports it.
- Use UTC instants for system timestamps.
- Add constraints and indexes intentionally.
- Do not create cross-service foreign keys.
- Do not access another service's database.
- Avoid N+1 query behavior.
- Use pagination for unbounded collections.
- Prefer keyset/cursor pagination for potentially large collections.

## Security Rules

These are non-negotiable:

- Never persist plaintext passwords, PINs, OTPs, refresh secrets, or verification tokens.
- Never log credentials, tokens, authorization headers, OTPs, or secret material.
- PendingRegistration cannot authorize anything.
- AccountGroup is a linking/navigation concept, not an authorization grant.
- Preferred account is navigation preference only.
- The account used for login receives the initial SessionAccountGrant automatically with `authMethod=LOGIN`.
- Other linked accounts require a valid challenge before receiving a grant.
- Multiple SessionAccountGrants may be active simultaneously.
- Do not introduce a global server-side `activeAccountId`.
- SessionAccountGrant alone is insufficient for organization/workspace authorization.
- OrganizationMembership revocation is a top-level kill switch for organization descendants.
- JWTs must remain small and must not contain the complete mutable permission graph.
- Downstream services validate JWT signature/issuer/audience/expiration locally.
- Use asymmetric signing and JWKS/key rotation.
- Use 401 for invalid/missing authentication and 403 for authenticated-but-forbidden access.
- Sensitive authorization fails closed when current permission cannot be established.
- Never trust arbitrary `X-User-Id` or similar client-controlled identity headers.
- Step-up authentication is an additional factor, not a permission grant.

## JWT / Session Rules

Suggested access-token claims:

```text
sub
sid
iss
aud
iat
exp
```

Do not add organization/group/workspace permission lists to the JWT merely for convenience.

Session state, refresh state, grant expiry, revocation, and mutable authorization must remain server-authoritative.

Use `SessionCreationPolicy.STATELESS` for normal access-token request processing.

## Registration Rules

Registration flow:

```text
PendingRegistration
-> verification
-> VERIFIED
-> transactional provisioning
-> User/UserAccount/LoginIdentity/AccountGroup
-> COMPLETED
```

Keep `VERIFIED` separate from `COMPLETED`.

Provisioning must be retry-safe/idempotent.

Do not create normal memberships/documents/sessions from an unverified registration.

## Authorization Cache Rules

Use:

```text
domain service Caffeine
-> shared IAM Redis
-> IAM internal authorization endpoint
-> IAM MySQL
```

- IAM is the only writer/deleter of shared IAM authorization Redis state.
- Domain services may read it and populate local Caffeine.
- Domain services must not mutate IAM authorization state in Redis.
- Kafka events invalidate local caches.
- Use authorization versions to reject stale state/events.
- Redis/Caffeine are disposable.
- New pods start with empty Caffeine.
- Do not bulk preload authorization state.

## Outbox / Kafka Rules

When a committed domain/security mutation must propagate asynchronously:

- update aggregate state and insert OutboxEvent in the same MySQL transaction
- publish only committed outbox records
- claim work in bounded batches
- do not hold DB transactions across Kafka/Redis network calls
- retry with bounded backoff
- include event ID and aggregate/version information
- make consumers idempotent
- tolerate duplicate and stale/out-of-order events

## Organization Revocation

A revocation implementation is incomplete unless it addresses:

```text
OrganizationMembership -> REVOKED
authorization version increment
outbox event
authorization cache invalidation/update
Kafka propagation
local Caffeine invalidation
relevant SessionAccountGrant revocation
durable user notification
safe account fallback
```

Revoked organization content must not leak through search, recent items, favorites, suggestions, autocomplete, root listings, or cached metadata.

## Document/Directory Rules

The Document service owns content metadata.

Use one self-referencing Directory entity:

```text
Directory
- workspaceId
- parentDirectoryId
- directDirectoryCount
- directDocumentCount
- descendantDirectoryCount
- descendantDocumentCount
- descendantSizeBytes
```

Do not create separate SubDirectory entities.

Prevent directory cycles.

Direct counters should normally be strongly consistent with direct metadata changes.

Descendant counters may be eventually consistent if maintained through outbox/Kafka to avoid hot-row contention.

Elasticsearch is not the authoritative directory/file counter.

At scale, use `workspaceId` as the metadata locality/sharding key.

Do not shard collaborative workspace metadata by user.

Document binaries belong in S3, not MySQL.

## Elasticsearch Rules

Elasticsearch is a reconstructible search projection.

Use it for names, extracted text, metadata, tags, MIME filtering, and authorized search.

Do not use it as the source of truth for:
- authorization
- exact transactional existence
- membership
- directory hierarchy
- security-sensitive counts

Every search path must enforce resource visibility.

## Coding Style

- Prefer explicit domain names over generic `Manager`, `Helper`, or `Util`.
- Keep controllers thin.
- Put use-case orchestration in application services.
- Keep security/domain invariants close to the domain/application layer.
- Avoid exposing JPA entities directly as REST DTOs.
- Use immutable request/response DTOs where practical.
- Validate external input at API boundaries and enforce invariants again where required by the domain.
- Prefer constructor injection.
- Keep transactions at application-service/use-case boundaries.
- Avoid remote/network calls while holding DB transactions.
- Do not hide important authorization behavior inside generic interceptors if doing so makes security rules difficult to test.
- Favor clear code over clever abstractions.

## Testing Requirements

Use Testcontainers for infrastructure integration tests.

Security-sensitive flows need negative-path tests.

At minimum, eventually test:

- successful/failed registration verification
- expired verification
- attempt limiting
- idempotent provisioning
- login success/failure
- JWT validation
- refresh rotation/replay
- logout/session revocation
- initial login-account grant
- linked-account unlock success/failure
- idle/absolute grant expiry
- account unlink
- organization membership activation/revocation
- revocation during active sessions
- group membership validity
- authorization cache miss/hit/invalidation
- stale authorization versions
- Redis outage
- Kafka outage
- duplicate Kafka events
- outbox retries
- signing-key rotation
- concurrent security operations
- application restart/pod loss

## Observability

For important flows expose:

- structured logs
- correlation/request IDs
- metrics
- traces where configured

Never put secret material or full tokens into observability data.

Useful metrics include:

- login successes/failures
- verification failures/expirations
- account unlock successes/failures
- authorization latency
- Caffeine/Redis hit rates
- IAM fallback calls
- outbox backlog/age
- Kafka publish failures
- authorization denials
- session/grant revocations

## Scope Discipline

Do not prematurely add:

- per-file ACL rows when workspace inheritance solves the requirement
- directory closure tables without demonstrated subtree-query need
- physical database sharding before capacity requires it
- new microservices solely for internal implementation details
- permission-heavy JWTs
- duplicate sources of truth for preferred account
- Elasticsearch-backed authorization

When a simpler implementation preserves `PROJECT_SPEC.md` invariants, prefer it.

## Before Finishing a Task

Check:

1. Does the implementation preserve the documented domain semantics?
2. Are security-sensitive state changes transactional where required?
3. Are credentials/secrets protected?
4. Are indexes/constraints/migrations included?
5. Are cross-service boundaries respected?
6. Are negative paths tested?
7. Did tests run successfully?
8. Did the change introduce an undocumented architectural decision?

If a new durable architectural decision was necessary, update `PROJECT_SPEC.md` in the same change.
