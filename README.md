# IAM/Auth service — Registration, sessions and linked-account unlock

Spring Boot 4.1.1, Java 25 and Maven 3.9.16 bootstrap for the Drive Platform.
Read `AGENTS.md` and `PROJECT_SPEC.md` before extending the service.

Architecture: [Auth flows and security boundaries](docs/auth-architecture.md) ·
[Platform services and infrastructure diagrams](docs/platform-architecture.md).
Next service: [Document implementation plan](document-service-plan/IMPLEMENTATION_PLAN.md).
Local service identity: [Keycloak setup and internal authorization](docs/internal-authorization.md#local-keycloak-issuer).

## Local service ports

All published ports bind to `127.0.0.1` only. Optional monitoring services become
available when their Compose profiles are started.

| Service | Localhost ports |
| --- | --- |
| Auth HTTP | 8080 |
| Keycloak development HTTP | 8082 |
| MySQL / X Protocol | 3306 / 33060 |
| Redis | 6379 |
| Kafka external listener | 9092 (container listener 19092) |
| RustFS API / console | 9000 / 9001 |
| Mailpit inbox / SMTP | 8025 / 1025 |
| Elasticsearch HTTP / transport | 9200 / 9300 |
| Kibana | 5601 |
| APM intake | 8200 |
| Prometheus | 9090 |
| Grafana | 3000 |

One-shot initialization/tooling and the log-only collector expose no host ports.
Auth's management port 9091 remains private to the Compose network.
Keycloak development login is `admin` / `admin` at
`http://localhost:8082/admin/`; secure issuer integration remains pending.

## API documentation

Local Compose enables Swagger UI at [http://localhost:8080/swagger-ui/index.html](http://localhost:8080/swagger-ui/index.html). The generated OpenAPI contract is available at `/v3/api-docs` (JSON) and `/v3/api-docs.yaml` (YAML).

For a direct launch, set `AUTH_API_DOCS_ENABLED=true` in Auth's existing `.env` and use the existing environment-loading launch workflow. Documentation is disabled by default outside local Compose; set `AUTH_API_DOCS_ENABLED=false` in production. No application endpoints become public by enabling documentation, and internal service authorization endpoints are excluded.

Create a registration, verify the emailed token, complete provisioning, then log in. Copy `accessToken` into **Authorize** without the `Bearer` prefix. Authorization is not persisted across page reloads. **Try it out** performs real API calls, including writes. Swagger uses JSON refresh-token transport unless browser cookie mode is explicitly selected with an allowed Origin.

Controller annotations supply operation summaries and descriptions. Request/response DTOs and Bean Validation supply schemas and constraints automatically. Secret inputs are write-only. Add annotations alongside new endpoints to keep the contract current.

## Run and test

Install JDK 25. The checked-in Maven wrapper uses Maven 3.9.16.
Docker must be running with Linux containers for the MySQL Testcontainers tests.
The tests always require Docker; infrastructure tests are not silently skipped.

```powershell
.\mvnw.cmd --batch-mode --no-transfer-progress verify
```

On Linux/macOS use `bash ./mvnw --batch-mode --no-transfer-progress verify`.
CI runs the same full build on a runner with Docker.

Local Maven runs (when `CI` is unset) reuse one MySQL Testcontainer across test
classes and subsequent runs, plus Redis/Kafka containers for infrastructure tests.
These containers stay running after the tests, and Ryuk is
disabled locally so it does not remove the container. Stop it manually in Docker
Desktop when needed. Tests clear registration, identity, session and audit data before each test; Flyway
history and schema remain available for the next run.

When `CI` is set, reuse is disabled and Ryuk performs automatic cleanup. To use
that cleanup behavior locally, pass `'-P!local-testcontainers-reuse'`.

For local application startup, create a dedicated MySQL 8.4 database named
`auth_service` with `utf8mb4` encoding and a dedicated database user. Supply
credentials through the environment or deployment secret management:

```powershell
$env:DB_USERNAME = '<database user>'
$env:DB_PASSWORD = '<database password>'
# Optional: DB_URL overrides shared MySQL host/port and private DB_NAME/DB_URL_OPTIONS.
$env:JWT_ACTIVE_KID = '<stable signing-key identifier>'
$env:JWT_PRIVATE_KEY = 'file:C:/secure/auth-private.pem'
$env:JWT_PUBLIC_KEY = 'file:C:/secure/auth-public.pem'
# Private key: PKCS#8 PEM; public key: X.509 PEM; RSA at least 2048 bits.
.\mvnw.cmd spring-boot:run
```

Never commit database credentials. Production deployments must configure the
appropriate MySQL TLS settings in DB_URL and their infrastructure.

## Run with Docker Compose

Docker Desktop with Linux containers is required. Prepare the local credentials before starting the unified stack:

The local development stack intentionally uses administrator access: Auth connects
as MySQL `root`, the optional TLS Keycloak database user has global administrator
privileges, and `unidocs_telemetry_writer` has Elasticsearch `superuser` access.
Kibana retains its supported `kibana_system` identity. Tests retain their isolated
schema/user. This user-authorized development exception replaces the earlier
restricted local database/collector identities; production still requires separate
least-privilege identities. All published ports remain bound to `127.0.0.1`.

Shared infrastructure is defined in `../docker/compose/`. Run Auth operations with `docker compose -p unidocs -f ../docker-compose.yaml`; Auth `docker-compose.yml` includes only its application, test runner and Filebeat. Preserve existing credentials, asset paths, containers and volumes; do not duplicate shared files, overlays or network declarations.

Common connections come from the existing workspace `../.env`: `SHARED_MYSQL_HOST` /
`SHARED_MYSQL_PORT`, `SHARED_STORAGE_ENDPOINT`, `SHARED_OTLP_TRACING_ENDPOINT`, and
`SHARED_KEYCLOAK_BASE_URL` / `SHARED_KEYCLOAK_REALM` (JWKS transport). The workspace
Compose include for Auth reads `env_file: [.env, auth-service/.env]`, relative to the
workspace root. Auth currently has no consumer for `SHARED_AUTH_BASE_URL`.

Shared containers read only workspace `../.env`; its `../.env.example` documents
infrastructure settings and credentials. Shared MySQL bootstrap uses
`MYSQL_PASSWORD`, RustFS uses `RUSTFS_ACCESS_KEY` / `RUSTFS_SECRET_KEY`, and Kafka
initialization uses `KAFKA_INIT_TOPIC`. `APM_SECRET_TOKEN` is shared with Auth's
trace exporter. Migration preserves existing values; Auth retains its own
`DB_PASSWORD`, `STUDENT_STORAGE_*` credentials and `OUTBOX_TOPIC`.

Shared static configurations are copied into workspace `docker/supporting_files/`,
alongside `docker/compose/`; shared includes resolve paths from the workspace root
with `project_directory: .`. Edit these shared copies for shared services. Runtime
and checker Prometheus configs remain distinct; Auth Filebeat stays local, while
retained-data mounts keep their existing locations. Generated shared files are
`metrics/auth-service-scrape-token`, `metrics/doc-service-scrape-token`, `keycloak/keycloak.p12` and
`keycloak/unidocs-services-realm.json` under root supporting files; setup maintains
these ignored copies without rotating existing keys. Auth keeps its signing keys,
certificate and truststore locally, plus the private metrics token and realm client
credential values used to generate the shared adapters.
Each service's generator maintains its matching shared token copy. Prometheus token
mounts use read-only long syntax with `create_host_path: false`; the container paths
`/run/secrets/metrics/scrape-token` and `/run/secrets/metrics/document-scrape-token`
remain unchanged.

Auth's ignored `.env` retains `DB_NAME` / `DB_URL_OPTIONS`, `AUTH_TEST_DB_NAME` /
`AUTH_TEST_DB_URL_OPTIONS`, credentials, identities, issuers, audiences and resource
names. Use both existing environment examples and `./scripts/prepare-local.ps1`;
setup persists shared settings in `../.env` and private settings in Auth's `.env`,
preserving existing values. Direct application launches support shared
fallbacks and explicit `DB_URL` overrides. Shared endpoints use container DNS;
host launches must supply reachable transport overrides. Local probes retain
localhost URLs. Private keys, certificates and generated adapters remain in
`.secrets/`; back up both environment files, `.secrets/` and database volumes.

```powershell
./scripts/prepare-local.ps1
docker compose -p unidocs -f ../docker-compose.yaml up --build -d --wait auth-service-dev
```

The app is available at `http://localhost:8080`; readiness is
`http://localhost:8080/actuator/health/readiness` and JWKS is
`http://localhost:8080/.well-known/jwks.json`. Compose publishes fixed localhost
ports as listed above. View application output with
`docker compose -p unidocs -f ../docker-compose.yaml logs --follow auth-service-dev`.

The multi-stage Dockerfile builds with Java 25 and the Maven 3.9.16 wrapper, then
runs the packaged app as UID 10001 on a Java 25 JRE. Image packaging skips tests;
run the normal Maven verification separately with Docker available.

Compose starts MySQL 8.4.8, Redis 8.2.10, Kafka 4.1.2 in single-node KRaft mode,
and the application. `prepare-local.ps1` preserves or initializes settings and
credentials in the environment file owned by each component, with the 3072-bit RSA key pair in `.secrets/`. The app
receives credentials through environment settings and reads PEM keys through
read-only mounts. Never commit these files or copy them into images. Preserve
`../.env`, Auth's `.env` and `.secrets/` with database/storage volumes to retain access and JWT trust.

Flyway applies migrations when the app starts. Compose waits for MySQL, Redis and
Kafka health and application readiness. Published service ports bind only to
`127.0.0.1`; container-to-container traffic retains its Compose network addresses.
This stack has its own volumes and does not alter the reusable test database.
Containers and volumes stay available until you stop them manually.

Local Compose sends registration, invitation and account-notice email to Mailpit at `http://localhost:8025` by default. SMTP is available on localhost port 1025 and inside Docker on port 1025. The Compose TLS/auth overrides apply only to this local inbox; production application defaults still require STARTTLS.

Outside Compose, SMTP delivery remains disabled by default. To use registration/invitations, supply
the existing SMTP settings through a local Compose override, including sender,
host, port and credentials, and enable the respective delivery flags. The existing
STARTTLS requirements still apply. Production deployments should
supply managed credentials and signing keys, TLS ingress and their operational policy.

### Standalone profiles and Swagger

Docker offline startup (no dependent services):

```powershell
./scripts/compose.ps1 -Profile offline up --build -d
```

Each application has explicit dev/test/offline/prod named services in its service YAML.
Use Docker profile flags directly or the optional `scripts/compose.ps1` profile wrapper.
The wrapper selects profiles only; application settings are defined in YAML.
See [Compose profiles](docs/COMPOSE_PROFILES.md) for setup, test isolation and monitoring.

Use `dev` for normal Auth development, including its existing dependencies and
security protections. Swagger is enabled in this profile.

Use `offline` for dependency-free diagnostic startup, including when MySQL is
unavailable. It loads no domain services, persistence, signing keys, Redis, Kafka,
SMTP, storage or service-identity integrations. Health/readiness report process
availability only. Auth APIs, including JWKS and internal authorization, return
503 with no-store responses; no identities, sessions or temporary data are created.
Swagger describes this reduced offline surface.

```powershell
./mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=offline"
# Normal development, with existing credentials and reachable infrastructure:
./mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=dev"
```

Swagger UI: `http://localhost:8080/swagger-ui/index.html`.
OpenAPI JSON: `http://localhost:8080/v3/api-docs`.
Maven does not automatically load `.env`. Normal development still needs the
existing environment credentials and signing-key settings; host launches need
reachable transport endpoints and host paths for signing keys. Preserve the
existing environment files and keys. `offline` also takes precedence when combined
with `dev`. Compose dependency ordering still applies to Compose launches.

### Redis, Kafka and Caffeine

The application is wired to Redis at `redis:6379` and Kafka at `kafka:9092` inside
Compose. Redis and Kafka use this private local Docker network; the local broker
uses plaintext and replication factor 1. Production requires appropriate Redis
authentication/TLS and Kafka security/replication configuration.

Redis is disposable storage, limited to 128 MB with `noeviction` and persistence
disabled. Expiring login counters must not be silently evicted; memory exhaustion
denies new admissions and cache writes. Kafka stores its log in the `kafka-data` named volume.
Automatic topic creation is disabled; topics must be created deliberately when
implementing their event consumers. For example, a local diagnostic topic:

```powershell
docker compose -p unidocs -f ../docker-compose.yaml exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --create --if-not-exists --topic local-smoke-test --partitions 1 --replication-factor 1
```

Caffeine runs inside the application JVM. Spring's cache manager uses Caffeine,
with a maximum of 10,000 entries per cache, 30-second expiry after writes and
statistics enabled. Caches start empty. Override `CAFFEINE_SPEC` when needed.
Redis clients have one-second connect/command timeouts. Kafka producers use string
keys/payloads, acknowledgement from all replicas, idempotence and bounded delivery;
consumers disable automatic offset commits. Kafka health probes have a two-second
wait and expose no broker details.

Compose enables Redis/Kafka health checks and includes them in readiness. Standalone
runs default to localhost client addresses with these optional infrastructure health
checks disabled; enable them with `AUTH_INFRASTRUCTURE_ENABLED=true` and configure
`REDIS_HOST`, `REDIS_PORT` and `KAFKA_BOOTSTRAP_SERVERS` for your network. To include
them in standalone readiness, set
`MANAGEMENT_ENDPOINT_HEALTH_GROUP_READINESS_INCLUDE=readinessState,db,redis,kafka`.

Spring provides injectable `StringRedisTemplate`, `KafkaTemplate<String, String>`
and `CacheManager`. Compose enables the organization snapshot cache and bounded
outbox publisher described below. Application services must not publish events
directly during database transactions.

### Versioned organization snapshots

Organization detail reads use Caffeine, then Redis, then MySQL to obtain a snapshot.
Every response still requires a fresh MySQL check of the session/account grant,
organization and membership status, authentication policy, role, membership ID and
both versions. Redis/Caffeine cannot grant access. Create/list operations retain
their existing MySQL paths. A Redis outage or malformed snapshot falls back to MySQL;
failure to establish current permission cannot return a cached response.

Shared entries are scoped by account and organization, with a jittered 20–30 second
TTL. Redis Lua scripts reject older organization/membership versions using exact
decimal comparison. Organization version floors last ten minutes and prevent late
writes from restoring invalidated snapshots. Related keys use one organization hash
tag for Redis Cluster; production must configure a cluster-aware client. Local
Caffeine starts empty and never preloads authorization state. Cache network calls
run outside database transactions; fresh SQL visibility checks hold shared locks.

The Kafka listener handles organization creation and membership activation events.
Each application instance uses its own consumer group to receive invalidations;
duplicate and out-of-order events cannot lower version floors. New instances start
at the latest offset with empty local caches. Cache-only effects are idempotent.
Future metadata, policy and membership mutations must increment authorization
versions and emit corresponding transactional events.

Standalone runs opt in with `AUTHORIZATION_CACHE_ENABLED=true` and
`AUTHORIZATION_CACHE_LISTENER_ENABLED=true`, after provisioning the outbox topic.
`AUTHORIZATION_CACHE_INSTANCE_ID` defaults to a random UUID; use a distinct value
per running instance. Compose enables both flags. Bounded `authorization.snapshot`
and invalidation counters expose cache outcomes without sensitive labels.
This is the first IAM read projection. The authenticated [internal account,
organization and group authorization endpoints](docs/internal-authorization.md) check fresh MySQL state;
domain-service caches and downstream content revocation belong to downstream slices.

### Transactional outbox delivery

Compose's one-shot `kafka-init` service creates `iam.domain-events.v1` with three
partitions and local replication factor 1 before starting the application. Set
`OUTBOX_TOPIC` to choose another topic. For standalone runs, explicitly provision
the topic and set `OUTBOX_ENABLED=true`; publication is disabled by default outside
Compose. Production topic replication and retention require deployment policy.

Every five seconds, the worker reserves up to 20 committed pending MySQL events
using `FOR UPDATE SKIP LOCKED`. Each claim has a random fencing token and a
60-second lease based on MySQL UTC time. It renews a valid claim immediately before
sending, waits at most 20 seconds for Kafka acknowledgement, then marks the row
published in another short transaction. Kafka metadata lookup is separately bounded
by the producer's existing `max.block.ms`. No database transaction spans Kafka I/O.

Failures leave events pending with exponential backoff from one second to five
minutes. Retry attempts count reservations, including recovered abandoned claims.
There is no automatic discard or terminal dead-letter state for security events.
`last_error` contains only `KAFKA_PUBLISH_FAILED`, never broker exception text or
payloads. Kafka's producer error listener is replaced to avoid logging record data.
Interrupted/process-lost workers leave their leases for automatic recovery. An
expired worker cannot renew or acknowledge another worker's reservation.

Delivery is **at least once**: Kafka acknowledgement followed by process/database
failure can deliver the same event again. The Kafka key is `aggregateType:aggregateId`.
The original JSON payload is preserved. Headers carry `eventId`, `aggregateType`,
`aggregateId`, `aggregateVersion` (also `version`), `eventType` and `occurredAt`.
Downstream consumers must deduplicate by event ID and reject stale aggregate versions;
cross-worker publication order is not guaranteed. The organization snapshot consumer
uses monotonic version floors. Other consumers and downstream content revocation
remain separate slices.

Configuration uses `auth.outbox.batch-size` (1–100), `lease-duration`, `send-timeout`,
`retry-initial`, `retry-max` and `poll-interval` (milliseconds). Set
`auth.outbox.scheduling-enabled=false` for controlled/manual delivery. Bounded
`outbox.delivery` outcome counters, `outbox.poll.failures` and
`outbox.oldest.pending.age.seconds` expose delivery and backlog age without IDs or
payloads in metric labels. Published rows remain available; retention is a later
operational policy.

## Bootstrap behavior

- Flyway owns schema changes; Hibernate only validates. Open Session in View is disabled.
- V1 establishes Flyway history; V2 adds pending registration and verification;
  V3 adds core identity, provisioning result constraints and security audit tables;
  V4 adds sessions, account grants and hashed refresh credentials;
  V5 adds account credentials, bound challenges and a versioned grant policy;
  V6 adds organization bootstrap, membership, policy and pending outbox records;
  V7 adds bound, expiring organization invitations;
  V8 adds scoped organization accounts, independent login identities and provisioning;
  V9 adds fenced outbox delivery leases and sanitized retry diagnostics;
  V10 adds organization-scoped groups and the GROUP_CREATED audit type.
- GET `/actuator/health`, `/actuator/health/liveness` and `/actuator/health/readiness`
  are anonymous. Readiness includes MySQL; liveness does not. Health details are hidden.
- Registration creation, verification, completion, login and refresh POSTs are anonymous.
  Verification/completion require the email token; refresh requires its opaque credential.
  JWKS is public. `/me`, `/me/accounts` and logout require a signed bearer JWT.
  Account challenge POSTs and the preferred-account PUT require bearer authentication
  and current database authorization. Organization creation and reads require bearer
  authentication and an explicit currently unlocked account with usable policy/membership.
  Other requests
  are denied: 401 for anonymous requests, 403 for an authenticated
  principal. Info and Prometheus are exposed but inaccessible until an explicit future
  operational authentication policy is implemented.
- Request handling is stateless. Basic authentication, form login, logout and request
  caching are disabled. No generated development user/password is created.
- CSRF is disabled for this API bootstrap, which provides no cookie authentication.
  Reevaluate this choice if browser cookie authentication is introduced.
- Errors use `application/problem+json`. Validation/parser errors and unexpected
  failures do not echo input, exception messages or stack traces.
- Logs use Spring Boot's Logstash JSON format. Each request gets a generated UUID
  `X-Request-Id` and an MDC `requestId`; client-supplied IDs are not trusted. No request
  bodies, authorization headers or credentials are logged by bootstrap components.

## Package and persistence conventions

The root is `com.unidocs.auth`. Implemented infrastructure is in `security.config`,
`shared.config` and `shared.error`. As features arrive, create capability packages
(`registration`, `user`, `account`, `authentication`, `credential`, `session`,
`organization`, `group`, `authorization`, `audit`, `outbox`) and their relevant
`api`, `application`, `domain`, `persistence` layers. Do not create later-phase
entities or controllers as placeholders.

Domain identifiers are `java.util.UUID`, mapped to MySQL `BINARY(16)`; new high-volume
records should use UUIDv7 once a suitable implementation is chosen. Phase 1 only
uses random UUIDs for ephemeral request correlation, not domain identifiers.
Use `Instant` for system timestamps and inject the UTC `Clock` bean for testable
application time. JDBC and Hibernate use UTC.

Organization bootstrap, invitations, dedicated organization accounts, and IAM
account lifecycle revocation are implemented below. Downstream content revocation
remains deferred. Group bootstrap, administrator assignments and reviewed join requests,
Kafka publication and the first Redis/Caffeine
organization snapshot projection are implemented; full service authorization is deferred.

## Registration and SMTP

Configure these environment variables through deployment secrets or your local
environment before enabling registration:

```text
REGISTRATION_SMTP_ENABLED=true
REGISTRATION_SMTP_FROM=no-reply@your-domain.example
SPRING_MAIL_HOST=<SMTP host>
SPRING_MAIL_PORT=587
SPRING_MAIL_USERNAME=<SMTP username>
SPRING_MAIL_PASSWORD=<SMTP password>
```

STARTTLS is required, mail debugging is disabled, and network timeouts are five
seconds. Disabled SMTP delivery returns 503 without creating a record. Enabling
SMTP requires a mail host and sender; missing required beans/configuration fails startup.
Tests replace delivery with an in-memory capture; they do not send real email.

Create a Personal email registration:

```http
POST /api/v1/registrations
Content-Type: application/json

{"displayName":"Jane Doe","email":"jane@example.com","password":"<12–128 characters>"}
```

The 201 response contains `id`, `status=PENDING_VERIFICATION`, and `expiresAt`.
The email contains a single-use verification token; the API never returns it.

```http
POST /api/v1/registrations/{id}/verify
Content-Type: application/json

{"token":"<token from email>"}
```

A valid token returns 200 with `status=VERIFIED`. No identity or session is created
by verification. Registrations expire after 24 hours,
codes after 5 minutes, with a maximum of five attempts. Invalid, expired, consumed,
unknown and locked tokens return sanitized 400. Passwords use salted PBKDF2 SHA-256;
Six-digit verification codes are stored only as salted BCrypt hashes.

Complete a verified registration using the same email token:

```http
POST /api/v1/registrations/{id}/complete
Content-Type: application/json

{"token":"<token from email>"}
```

Completion returns 200 with `id`, `status=COMPLETED`, `userId`, `accountId`,
`accountGroupId`, and `completedAt`. It transactionally creates the user, empty
profile, verified email contact, preferences, Personal account, login identity,
initial account group/link and security audit records. It creates no session or
resource permissions. The response uses `Cache-Control: no-store`.

Retries with valid proof return the same IDs and completion timestamp without
duplicate identity or audit rows. After successful verification, this token can
complete/retry until the original 24-hour registration deadline, even when its
five-minute verification window has passed; it still cannot verify twice or log in.
Unknown/unverified registrations, wrong or missing proof and expired completion
deadlines receive sanitized 400. A login email already owned by another completed
registration receives sanitized 409; identity creation rolls back entirely.
Failed provisioning leaves `VERIFIED` available for retry within the deadline.

The preferred account initially points to Personal and affects navigation only.
Defaults are theme SYSTEM, time zone UTC, no locale override, email/push
notifications off, and security notifications on. Profile fields are not inferred
from the display name. Integration suites share the reusable container but run
sequentially and reset their data between tests.

SMTP sends after commit. A delivery failure returns 503 and leaves a pending record.
Submit a new registration to retry delivery; duplicate pending email registrations
are allowed. Resend, durable delivery retry, cleanup, and registration-wide rate
limiting are future slices. Pending records grant no access.

Surefire uses a direct classpath (`useManifestOnlyJar=false`) so Windows checkouts
and Maven caches on different drives work. Framework request logging and SQL/bind
logging have explicit safe levels; do not enable logging that exposes secrets.

## Login and durable sessions

`POST /api/v1/auth/login` accepts `{"email":"jane@example.com","password":"<password>"}`.
Only completed, active identities with active users/accounts/groups and a current
link can log in. Unknown identities and incorrect passwords return the same
sanitized 401. Password verification runs before acquiring transaction locks;
the transaction rechecks the credential hash/version and availability.

The response contains `tokenType=Bearer`, `accessToken`, `expiresIn=300`,
`refreshToken`, `sessionId` and `loginAccountId`. Token responses use `no-store`.
Use `Authorization: Bearer <accessToken>` for `/api/v1/me`,
`/api/v1/me/accounts?limit=50&after=<last account UUID>`, and
`POST /api/v1/auth/logout`. Navigation returns accounts and a nullable `nextCursor`;
page sizes are 1–100. Linked accounts without a current grant show `unlocked=false`,
including when preferred. This listing grants no organization/workspace access.

Each login creates its own durable 12-hour session and initial `LOGIN` account
grant. The grant has a 30-minute idle limit and the session's 12-hour absolute
limit. Successful IAM reads and refreshes renew idle activity within the absolute
limit. Expired grants require a new login; refresh cannot resurrect them.
IAM reads/refreshes check current MySQL session, grant, link, account/user/group
status, credential reference/version and policy version. Any surviving valid account
grant can sustain the umbrella session; the JWT subject remains the original login
account. A valid JWT alone cannot bypass revocation.
Logout revokes the session, all account grants and all refresh credentials in
one transaction; repeating logout with the same unexpired JWT returns 204.

`POST /api/v1/auth/refresh` accepts `{"refreshToken":"<opaque credential>"}`.
Refresh credentials have a public UUID selector and 256 random secret bits;
only SHA-256 secret hashes are stored. Each successful refresh consumes the
credential and returns a replacement with the same absolute session deadline.
Consumed credentials remain available for replay detection. Reusing one with a
valid secret commits whole-session revocation and returns 401. Concurrent refresh
calls therefore produce one successful rotation and one replay that revokes the
winning credential too. Clients must serialize refreshes; there is no retry grace
window. Wrong secrets do not revoke sessions. Lost refresh responses require a
new login. Credential cleanup is a future slice and must retain consumed tokens
until the session's absolute deadline.

JWTs use RS256 and contain only `sub` (login account UUID), `sid`, `iss`, `aud`,
`iat` and `exp`. Default issuer/audience are `urn:unidocs:auth` / `urn:unidocs:drive`;
set `JWT_ISSUER` and `JWT_AUDIENCE` consistently with downstream validators.
JWKS is at `/.well-known/jwks.json`, caches for 60 seconds, and contains public
keys only. Signing keys must be provisioned through protected files/secret mounts;
missing/mismatched keys fail startup. No production key is generated at startup.
Tests alone generate in-memory keys. Keep the same key files across restarts.

To rotate keys, deploy the new active key/kid and retain prior public keys through
`JWT_RETAINED_PUBLIC_KEYS=old-kid=file:C:/secure/old-public.pem` (comma-separated
entries for multiple keys). Publish new public keys to validators before switching
signing across pods; retain prior verification keys for at least the five-minute
token lifetime plus downstream JWKS caching. Do not reuse a kid for another key.
IAM validates locally against the configured public key ring, including issuer,
audience, UUID claims, issuance time and exact expiration, without network calls.
JWT clock skew is zero; synchronize service clocks. Downstream services must check
live authorization/grant state for sensitive operations; local JWT verification
alone cannot establish mutable resource permissions.

Security audits record login results, session revocations and refresh replay with
IDs/type/time only; unknown-login failures have nullable identity IDs. Metrics
use bounded outcome/reason labels. Asynchronous consumers and outbox propagation
remain future phases; this slice authorizes only the IAM identity/navigation API.
Login throttling is now implemented; see the Login attack protection section below.

## Linked accounts and PINs

Prepare an authenticated account challenge:

```http
POST /api/v1/accounts/{accountId}/challenges
Authorization: Bearer <accessToken>
Content-Type: application/json

{"purpose":"UNLOCK","method":"PASSWORD"}
```

The response contains `id`, `accountId`, `purpose`, `method` and `expiresAt`.
Challenges expire after two minutes (or the session deadline, if earlier), allow
five attempts, and are bound to that session, target account, purpose, method,
credential ID/version and policy version. The UUID alone supplies no proof.

```http
POST /api/v1/accounts/{accountId}/challenges/{id}/complete
Authorization: Bearer <accessToken>
Content-Type: application/json

{"secret":"<target account password>"}
```

Successful UNLOCK consumes the challenge and creates/replaces only that account's
grant with `authMethod=PASSWORD` or `PIN`. Other grants stay unlocked. Each renewed
authentication gets the current policy's idle/absolute limits, capped by the
session's original absolute deadline. Responses contain unlock/termination state,
navigation preference and grant deadlines, with `Cache-Control: no-store`.
Invalid proof, replay, unavailable/unowned targets and unsupported methods receive
sanitized 403; invalid/missing session authentication receives 401.

To enroll/change a PIN, first unlock that account, prepare a `SET_PIN` challenge
with `method=PASSWORD`, then complete with `{"secret":"<account password>","newPin":"<6–12 digits>"}`.
The password remains authoritative in LoginIdentity; it is not copied to an unlock
credential. AccountCredential stores a salted PBKDF2 PIN hash with its own version.
Changing PIN increments that version and revokes all prior PIN grants for the
account across sessions. Password grants remain valid; the changing session can
use its fresh password proof to replace an invalidated PIN grant.

PIN unlock uses `method=PIN` and puts the PIN in `secret`. Five failed PIN proofs
across any challenges/sessions lock that credential for 15 minutes. Expiry allows
another attempt; successful proof clears the failure count. A valid existing grant
is not revoked by an attacker's incorrect PIN attempts. PASSKEY is reserved at the
verifier interface and fails closed until a WebAuthn adapter is implemented.

`LINK` challenges prove control before attaching a currently disconnected/unlinked
account already owned by the same human to the current group. They do not create a
grant or change preference. This slice does not merge independently registered
humans, create organization accounts, or implement their provisioning flow.

`UNLINK` challenges require target-account proof, mark its link disconnected, revoke
all its account grants, and invalidate pending target challenges in one transaction.
The current session terminates if no valid grant survives; other affected sessions
terminate lazily on their next IAM read/refresh. If another grant survives, refresh
and navigation continue while the original `sub`/`sid` remain unchanged. This does
not introduce a global active-account ID. A disconnected account cannot use the
current group-based login flow until re-linked; standalone-account login semantics
are a future slice.

`PUT /api/v1/me/preferred-account` accepts `{"accountId":"<owned linked account UUID>"}`
and changes navigation only, including for locked accounts. If unlink removes the
preferred account, fallback chooses the oldest available Personal account (UUID
breaks creation-time ties). Without Personal, the sole available organization account
becomes preferred; several require a selector (null preference), as does no available
account. An unavailable or expired fallback grant stays locked.

The durable GLOBAL SessionGrantPolicy defaults to 30 idle minutes and 12 absolute
hours, with multi-account grants and reauthentication required. Grants/challenges
reject stale policy versions. No policy administration API is exposed yet; future
administration must increment version and propagate security changes transactionally.
Proof verification and PIN hashing run outside database transactions; final writes
recheck the locked credential and binding. Locks follow session â†’ group â†’ credential
and grant; login takes group before identity to avoid crossing that order. Public
authentication/account use cases reject inherited transactions before proof work.
Audits and bounded metrics cover proof failures, linking/unlinking, unlock, PIN
changes and navigation preference. No resource permissions are granted. Asynchronous
projection/outbox propagation remains deferred until those consumers are introduced.

## Organization bootstrap

`POST /api/v1/organizations` accepts:

```json
{"accountId":"<unlocked account UUID>","requestId":"<retry UUID>","name":"Example Org","slug":"example-org","type":"COMPANY"}
```

Types are COMPANY, UNIVERSITY and CUSTOM. Names are limited to 100 characters;
slugs are globally unique, lowercase, 3–63 characters with single hyphen separators.
A current LOGIN/PASSWORD account grant is required. Creation activates an OWNER
membership for the selected existing account, with its human's verified primary
email. It creates an enabled PASSWORD policy with PIN unlock disabled and MFA
not required. Dedicated organization accounts use invitation provisioning below.

Matching retries return the same organization with HTTP 201 and a Location header.
Changing a payload under the same account/request ID or colliding with a slug returns
409. All responses and errors avoid disclosing another organization's details.

`GET /api/v1/organizations/{id}?accountId=<UUID>` requires a current account grant,
ACTIVE organization/membership and a usable organization policy. Inaccessible IDs
return 403. `GET /api/v1/me/organizations?accountId=<UUID>&limit=50&after=<UUID>`
lists only authorized organizations with keyset pagination (limit 1–100). Responses
include IDs, name, slug, type, caller role, membership/auth versions and creation time;
they omit member contact details. Authorization reads check MySQL on each request.
JWT claims, account linking and navigation preference do not carry organization grants.

Creation writes two security audits and a pending ORGANIZATION_CREATED outbox envelope
in the same transaction. The envelope contains IDs, versions and timestamp only.
The bounded `organization.bootstrap` outcome metric covers successful/retried creation,
conflicts and domain denials. The separate outbox publisher delivers these envelopes
when enabled. Policy administration is not exposed by this bootstrap slice.
IAM removal and revocation are exposed by the account lifecycle APIs below.
MFA-required/domain-restricted policy fails closed until its proof flow is implemented.

## Organization invitations for verified accounts

Enable invitation SMTP with `ORGANIZATION_INVITATION_SMTP_ENABLED=true` and
`ORGANIZATION_INVITATION_SMTP_FROM=<sender>`, using the existing Spring Mail settings.
Issuance fails with 503 when invitation delivery is unavailable. Tokens are mailed
after commit; they are never returned in the API response or stored as plaintext.

An unlocked OWNER/ADMIN sends:

```http
POST /api/v1/organizations/<organization UUID>/invitations
Authorization: Bearer <access token>
Content-Type: application/json

{"accountId":"<issuer's unlocked UUID>","email":"member@example.com"}
```

The 201 response contains invitation ID, organization ID, PENDING status and expiry.
Only MEMBER roles can be activated through this API. A LOGIN/PASSWORD account grant
is required even if the organization allows PIN for ordinary reads. Invitations expire
in 24 hours. Issuing another invitation for the same normalized address supersedes
the previous pending invitation with a new proof and deadline. Reissue is also the
recovery path for SMTP failure (503 can follow a committed invitation). Use the new
invitation ID/proof; older proofs no longer authorize acceptance.

The recipient must finish verified registration and sign in, then submit:

```http
POST /api/v1/organizations/<organization UUID>/invitations/<invitation UUID>/accept
Authorization: Bearer <access token>
Content-Type: application/json

{"accountId":"<recipient's unlocked UUID>","token":"<proof from email>"}
```

The verified primary contact and selected account's active EMAIL login identifier must
both match the invitation. Acceptance also rechecks the issuer's membership/version
and organization policy. Five wrong proofs fail the invitation; invalid/expired proofs
return generic 403. Wrong-email actors do not consume the recipient's attempts.

The 200 response is the authorized organization view with MEMBER role. Activation,
organization version increment, invitation consumption, audit and pending outbox events
commit together. Matching retries return the same membership without duplicate events;
revoked memberships cannot be resurrected. Invited registration,
administrative role changes and downstream content revocation remain future
slices. Acceptance adds membership to the chosen existing account and does not create
or unlock accounts, change preference, or modify JWT claims. Delivery/issuance/acceptance
expose bounded `organization.invitation.*` outcome metrics.

## Dedicated organization accounts

A verified, signed-in human can use an invitation to create an independent organization
account instead of adding membership to an existing Personal account:

```http
POST /api/v1/organizations/<organization UUID>/invitations/<invitation UUID>/provision-account
Authorization: Bearer <access token>
Content-Type: application/json

{"accountId":"<source account with LOGIN/PASSWORD grant>","token":"<proof from email>","displayName":"Work","password":"<new independent password>"}
```

The invited address may differ from the human's verified primary email. The email proof
establishes the official organization contact. Passwords must be 12–128 characters and
names 1–100 characters. The 200 response contains account, organization and membership
UUIDs, account type (COMPANY/UNIVERSITY/CUSTOM) and display name; it uses `no-store`.
Matching retries require the same source account, proof, name and password and current
authorization. Existing or revoked memberships for this human/organization return 409.
The existing-account acceptance endpoint and provisioning cannot consume one invitation
in different modes. Issuer authority, expiry and proof attempt limits are rechecked.

The new account joins the same human's AccountGroup with an INVITATION link and receives
its own hashed password and ACTIVE MEMBER membership. These changes, invitation
consumption, authorization version, audits and pending outbox events are transactional.
Provisioning creates no session or account grant and leaves preference unchanged.

To sign in directly, use `POST /api/v1/auth/accounts/<new account UUID>/login` with
`{"password":"<new independent password>"}`. It returns the standard token response,
with only this account's initial LOGIN grant. Existing Personal email login continues
at `/api/v1/auth/login`. Alternatively, explicitly unlock the linked organization
account through its PASSWORD challenge in an existing session. Provisioning and linking
alone leave that account locked.

Organization-account login, live grants, challenges and navigation recheck current
organization/membership and usable policy in MySQL. Disabled/revoked roots are hidden
from account listings and cannot log in or unlock. PIN unlock also requires enabled
organization PIN policy. A surviving Personal grant keeps the umbrella session usable
without changing JWT subject; no surviving grant ends the session on the next check.
Lifecycle actions now reconcile sessions immediately, persist notices, and publish
versioned removal/restoration/purge events. The snapshot cache handles lifecycle
invalidations. Downstream content services still need their consumers.
The bounded `organization.account.provision` metric records successful/retried/failed proofs.

## Organization group bootstrap

Account lifecycle removal, recovery, administrator review, organization-only
blacklists, security notices, and automatic retention purge are now available.
See [account lifecycle API and Docker configuration](docs/account-lifecycle.md).
Set `ACCOUNT_RETENTION_MONTHS` to `3` or `12`; configure security-notice SMTP
delivery before using removal. This implements the IAM revocation contract;
future content services must consume the versioned purge/invalidation events.

Group management requires a current organization OWNER/ADMIN membership and an
unlocked LOGIN/PASSWORD account. The server checks the current session, grant,
membership, organization and policy for every request; linked accounts, PIN grants
and cached organization snapshots cannot supply administrative authority.

Create a root or child with `POST /api/v1/organizations/{organizationId}/groups`:

```json
{
  "accountId": "<unlocked-admin-account-uuid>",
  "requestId": "<new-request-uuid>",
  "name": "Engineering",
  "type": "DEPARTMENT",
  "parentGroupId": null
}
```

Types are `DEPARTMENT`, `COURSE`, `CLASS`, `TEAM`, `PROJECT` and `CUSTOM`. Names are
trimmed, at most 100 characters and cannot contain control characters. Matching
request retries return the same group (201); changed payloads using the same request
ID return 409. Parent groups must be active in the same organization. Parents are
immutable, cycles cannot be introduced through creation, and hierarchy depth is
limited to 32. Disabled ancestors hide their descendants.

Use `GET /api/v1/organizations/{organizationId}/groups/{groupId}?accountId=...` for
detail or `GET /api/v1/organizations/{organizationId}/groups?accountId=...&limit=50`
for the administrative catalog. Lists contain `groups` and `nextCursor`; pass the
cursor as `after` to fetch the next page. Limits are 1–100. Responses use no-store;
unknown/inaccessible group or parent IDs return sanitized 403 responses.

Creation commits the group, security audit and version-1 `GROUP_CREATED` outbox
event together. Events contain IDs and versions, without group names or secrets.
The existing Kafka publisher handles delivery. Group creation adds no membership,
account grant or workspace permission. Administrator assignments and revocation,
custom role strings, validity windows and effective membership reads are available:
see [group membership APIs](docs/group-memberships.md). Discovery and joining rules,
scoped group administrators, invitations and trusted university semester enrollment
are available: see [group discovery and enrollment APIs](docs/group-discovery-and-enrollment.md).
Only APPROVAL groups accept [join requests](docs/group-join-requests.md). Directory sync
and hierarchy/status mutations remain later slices.


## Registration testing with Mailpit

Run `docker compose -p unidocs -f ../docker-compose.yaml up --build -d --wait auth-service-dev`, then open http://localhost:8025.
Register through `POST /api/v1/registrations`, read the six-digit code in the HTML or plain email,
and submit it as `token` to the verification/complete endpoints. The code expires after exactly
five minutes and is limited to five attempts. The API and application logs never return the code.

Student admission and administrator-created employee credentials are documented in
[registration-admission.md](docs/registration-admission.md). Local student ID evidence is stored
in a private RustFS bucket with credentials from `.env`; its API and console
are exposed only on localhost ports 9000 and 9001.
Keep `../.env`, Auth's `.env`, `.secrets/` and database/storage volumes together on subsequent starts.


### Forgot password and local Graphify

Personal/student recovery uses a five-minute email OTP. Organization employees request a current
administrator to issue a one-use recovery PIN, valid until used; five wrong attempts require reissue.
See [password recovery APIs](docs/password-recovery.md) for request/response examples, linked-account
selection, legacy organization accounts and security rules. Development messages appear in
[Mailpit](http://localhost:8025/); Compose enables PASSWORD_RECOVERY_EMAIL_ENABLED.

Graphify now uses [project-local extraction](docs/graphify-local.md). Run
`./scripts/graphify-local.ps1 -Phase prepare`, let Codex extract uncached documentation listed in the
request file, then run `./scripts/graphify-local.ps1 -Phase finalize`. This disables separate external
Gemini extraction while retaining documentation semantics and the graph/report/HTML maintenance rule.


## Security plan and reusable local tests

The phase-by-phase hardening plan is [CODEX_AUTH_SECURITY_IMPLEMENTATION_PLAN.md](docs/CODEX_AUTH_SECURITY_IMPLEMENTATION_PLAN.md).
Personal registration strips and lowercases email in its request DTO before validation;
password bytes and trusted server-owned identity/role/status defaults are preserved.

Run MySQL registration/security suites with the existing shared `unidocs` MySQL:

```powershell
./scripts/test-compose.ps1 -Build
# Later runs reuse the tools image/container and cached dependencies:
./scripts/test-compose.ps1
# A targeted MySQL/isolated suite:
./scripts/test-compose.ps1 -Tests 'RegistrationRequestTests,RegistrationProvisioningIntegrationTests'
```

`-Build` refreshes the `auth-service-test` image, which contains the application and test tooling.
It belongs to the same Compose project and remains running. Source is read-only;
Maven output/cache and a generated database credential use private named volumes.
The script provisions only `auth_service_test` with a separate schema-restricted user
and never clears the development `auth_service` database. No database host port or
Docker socket is needed. Password values are not printed or passed as SQL command-line arguments.
Run one database suite at a time.

The harness accepts test-only `AUTH_TEST_DB_URL`, `AUTH_TEST_DB_USERNAME`, and
`AUTH_TEST_DB_PASSWORD` together, validates the exact test schema and connection
options, and checks the actual selected database before cleanup. Without those
settings, normal CI/default infrastructure tests retain Testcontainers. The Compose
runner now supports MySQL-based, Redis-only and isolated suites; the older combined
Redis/Kafka and S3 bases need separate reuse setup in this socket-free runner.
The normal full CI suite remains unchanged in intent.

The default test command preserves existing MySQL and runner containers. `-Build` permits replacing only the tooling runner when its image changes; MySQL is always reused. Before each run, the dedicated test user's previous privileges are revoked and access is granted only to `auth_service_test`.


## Login attack protection

Login protection is enabled by default and requires Redis. Email, account UUID and
employee username login share expiring account counters; source IP and IP/account
counters also limit repeated failures and concurrent attempts. Defaults are 50 source,
10 account and 5 pair failures or in-flight attempts in a fixed 15-minute window. Success clears only captured
account/pair failures and preserves IP-wide history. Blocks return the same generic
401 as incorrect credentials and do not permanently lock activated accounts. Employee
temporary credentials retain their five-failure administrator-reissue rule.

Only the socket peer is trusted. Behind a proxy, that proxy is the source until trusted
proxy handling is explicitly configured. Redis admission outages fail closed. Compose
uses noeviction so memory pressure cannot discard protection counters; plan capacity
for shared caches and login state. Configuration uses LOGIN_ATTACK_PROTECTION_ENABLED,
KEY_PREFIX, WINDOW, IP_LIMIT, ACCOUNT_LIMIT and PAIR_LIMIT under the same prefix.

The reusable test script now also starts the existing Redis container without
recreating it and applies the noeviction policy in place. Redis tests use database 15
with isolated key namespaces; no FLUSHALL/FLUSHDB or container stop is needed. Run:

```powershell
./scripts/test-compose.ps1 -Tests 'LoginAttackProtectionTests,LoginAttackProtectionIntegrationTests,AuthenticationServiceTests,LoginRequestTests,EmployeeServiceTests,AuthenticationIntegrationTests,AdmissionAndEmployeeIntegrationTests'
```

After code changes, run `graphify update .` directly. Host-agent semantics process only
changed documentation, followed by the existing local incremental finalization.

Local Elasticsearch/Kibana log collection and OTLP APM containers are available through
[the optional observability Compose setup](docs/observability/docker.md).
The local Kibana UI is at http://localhost:5601. Generate credentials with
scripts/prepare-observability.ps1; the ignored environment file is preserved on
repeat runs. The optional stack keeps telemetry outside auth readiness and uses
separate bootstrap, collector, Kibana and intake identities.

Local configurable administrator logins use `admin` / `admin123`. RustFS requires an eight-character secret and uses `admin` / `admin1234`. Reserved MySQL `root`, Elasticsearch `elastic` and Kibana `kibana_system` identities retain their names with password `admin123`; isolated test identities and cryptographic keys/tokens remain distinct.

