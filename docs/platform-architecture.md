# Auth platform and infrastructure architecture

This guide shows the architecture configured in this repository. Optional Compose
the unified Compose file defines telemetry and dashboards; a diagram connection does not imply that
the corresponding container is currently running. See [Auth internals](auth-architecture.md)
for identity flows and [internal authorization](internal-authorization.md) for the
Document integration contract. [PROJECT_SPEC.md](../PROJECT_SPEC.md) owns platform semantics.

Solid arrows show implemented/configured connections. Dashed arrows identify future
services or deployment integrations. Arrow labels distinguish writes/exports from
queries and scrapes.

## High-level service map

```mermaid
flowchart TB
    Client["Browser / API client"] -->|"User API"| Auth["IAM / Auth service"]
    subgraph Business["Business infrastructure"]
        MySQL[("MySQL: IAM state, audit, outbox")]
        Redis[("Redis: protection state and authorization snapshots")]
        Kafka["Kafka: domain and security-audit topics"]
        Mail["Mailpit: local SMTP capture"]
        Evidence[("RustFS: student evidence, S3 API")]
    end
    Auth -->|"Transactions / SQL"| MySQL
    Auth -->|"Counters and IAM-owned projections"| Redis
    Auth -->|"Committed outbox publishing"| Kafka
    Kafka -->|"Versioned cache invalidation"| Auth
    Auth -->|"SMTP delivery"| Mail
    Auth -->|"Evidence upload / retrieval"| Evidence
    subgraph Telemetry["Optional observability"]
        Logs["Docker stdout log files"]
        Filebeat["Filebeat collector"]
        APM["Elastic APM / OTLP receiver"]
        Elastic[("Elasticsearch: diagnostic logs and traces")]
        Kibana["Kibana: logs and trace exploration"]
        Prom["Prometheus: metrics and rule evaluation"]
        Grafana["Grafana: metrics dashboards"]
    end
    Auth -->|"ECS JSON stdout"| Logs
    Logs -->|"Read-only collection"| Filebeat
    Filebeat -->|"Buffered log ingestion"| Elastic
    Auth -->|"OTLP HTTP traces"| APM
    APM -->|"Trace ingestion"| Elastic
    Kibana -->|"Query logs / traces"| Elastic
    Prom -->|"Bearer-authenticated metrics scrape"| Auth
    Grafana -->|"PromQL through provisioned datasource"| Prom
    Document["Document service: future deployment"] -.->|"Service JWT plus delegated user JWT"| Auth
    Auth -.->|"Fetch trusted HTTPS JWKS"| Issuer["External service identity issuer: configure before enabling"]
```

MySQL is the authoritative IAM store. Redis/Caffeine are disposable; Kafka moves
committed events. Elasticsearch stores diagnostic/search projections and does not
authorize users. Grafana and Kibana are separate viewing tools: Grafana reads
Prometheus metrics; Kibana reads Elastic logs and traces. Auth does not send
diagnostic logs directly to Elasticsearch.

## What each connection does

| Component | Auth relationship | Ownership and durability |
| --- | --- | --- |
| MySQL | JPA/JDBC transactions; Flyway migrations; sessions, grants, credentials, memberships, audit and outbox | IAM source of truth; no downstream direct database access |
| Redis | Rate limiting/login protection and IAM-written organization snapshots/version floors | Protection counters and disposable projections; snapshot outages can fall back to MySQL, while protection behavior follows its fail-closed policy |
| Caffeine | Bounded local organization snapshots/version floors inside each JVM | Starts empty; a cached snapshot cannot replace fresh authorization guards |
| Kafka | Outbox publishes domain/security events; IAM listener invalidates local authorization state | Asynchronous propagation; duplicate/stale events require version handling |
| Mailpit | Local registration, invitation and account-notice SMTP capture | Development delivery target; production supplies its mail provider |
| RustFS | S3-compatible student evidence storage adapter | Evidence binaries, separate from MySQL metadata; Document binaries belong to Document-owned S3 storage |
| Filebeat | Reads Docker stdout files, selects Auth ECS events, buffers delivery | External collector with persistent registry/disk queue; not the durable audit ledger |
| Elastic APM | Receives authenticated OTLP trace exports and writes trace data to Elastic | Optional telemetry; sampling does not replace audit history |
| Elasticsearch | Receives logs from Filebeat and traces from APM | Current use is observability; document search indexing is a future Document slice |
| Kibana | Queries Elasticsearch and provides log/trace exploration | UI configuration; no authority over auth state |
| Prometheus | Scrapes private Actuator metrics and evaluates rules | Local seven-day/512 MB configured metric retention; alert delivery is a separate deployment concern |
| Grafana | Server-side Prometheus datasource and provisioned Auth dashboard | Dashboard state in its volume; anonymous access and local unified alerting are disabled |

## Logs, traces, metrics and durable audit

```mermaid
flowchart LR
    Request["Auth operation"] --> Mutation["Domain/security mutation"]
    Mutation --> TX["One MySQL transaction"]
    TX --> State[("Domain state")]
    TX --> Audit[("SecurityAuditEvent, where required")]
    TX --> Outbox[("OutboxEvent, where required")]
    Outbox --> Relay["Claim committed batch; publish outside transaction"]
    Relay --> Topics["Kafka domain / security-audit topics"]
    Topics -.-> Consumers["Downstream consumers / audit archival"]
    Request --> ECS["ECS diagnostic stdout"]
    ECS --> FB["Filebeat"]
    FB --> ES[("Elasticsearch")]
    Request --> Span["Micrometer / OpenTelemetry span"]
    Span --> OTLP["Elastic APM"]
    OTLP --> ES
    Request -->|"Record measurements"| Metrics["Actuator / Micrometer metrics"]
    Prom["Prometheus"] -->|"Scrape"| Metrics
    Graf["Grafana"] -->|"Query"| Prom
    Kib["Kibana"] -->|"Query"| ES
```

MySQL audit rows are durable facts; the matching audit envelope can also be queued
transactionally for Kafka. Diagnostic logs, sampled traces and metrics serve
investigation/operations. Kafka delivery retries through the outbox without holding
database transactions across network calls. Audit archival consumers shown here
are a downstream integration, not a deployed archive in this repository.

## Local network and dashboard topology

```mermaid
flowchart LR
    Host["Developer host / browser"] -->|"127.0.0.1:8080"| API["Auth API: 8080"]
    Host -->|"127.0.0.1:9090"| P["Prometheus: 9090"]
    Host -->|"127.0.0.1:3000"| G["Grafana: 3000"]
    Host -->|"127.0.0.1:5601"| K["Kibana: 5601"]
    Host -->|"127.0.0.1:8025"| M["Mailpit UI: 8025"]
    subgraph Shared["Auth network namespace"]
        API
        P
        Management["Private management: 127.0.0.1:9091"]
    end
    P -->|"Scrape token; loopback only"| Management
    G -->|"http://auth-service:9090"| P
    K -->|"Private network; service credentials"| E["Elasticsearch: 9200"]
```

The metrics service uses `network_mode: service:auth-service` for Prometheus.
Consequently `127.0.0.1:9091` is reachable by Prometheus in that shared namespace,
and Grafana reaches Prometheus through `auth-service:9090`. Management port 9091
has no host publication. Grafana has its own admin credential and never receives
the Auth scrape token.

MySQL 3306, Redis 6379, Kafka 9092, RustFS 9000/9001, SMTP 1025, Elasticsearch 9200
and APM 8200 are internal Compose endpoints in these files. Host ports shown above
are default values and can be overridden. Local Elastic HTTP and Kafka PLAINTEXT
are development settings; production transport security remains a deployment slice.

## Platform service ownership and future integration

```mermaid
flowchart LR
    Client["Frontend / API client"] -.-> Gateway["Gateway / load balancer: planned"]
    Gateway -.-> IAM["IAM / Auth"]
    Gateway -.-> Docs["Document service: planned"]
    Docs -.->|"Local signature checks using public JWKS"| IAM
    Docs -.->|"Fresh account / organization / group evidence"| IAM
    IAM --> IAMDB[("IAM MySQL")]
    Docs -.-> DocDB[("Document-owned metadata database")]
    Docs -.-> S3[("Document-owned S3 binaries")]
    Docs -.-> Search[("Document search projection: Elasticsearch")]
    IAM --> Bus["Kafka"]
    Docs -.-> Bus
    Bus -.-> Notification["Notification service: planned"]
    Bus -.->|"Revocation/version events"| Docs
```

IAM owns identity, session grants and organization/group authority. Document owns
workspace permissions, directories, metadata and resource visibility. The internal
authorization routes are implemented but disabled until separate service-token
trust is configured. Document, gateway, notification delivery service, document
indexing and downstream authorization caches shown here are future integrations.
Each service owns its data: no cross-service database reads or foreign keys.

## Availability boundaries

Elasticsearch, Filebeat, APM, Kibana, Prometheus and Grafana are absent from Auth
Compose `depends_on` and application readiness dependencies. Their outage can lose
or delay observability data without becoming an authorization grant or a login
dependency. Filebeat buffering is bounded; it cannot promise unlimited outage recovery.

Current Compose startup waits for MySQL, Redis, Kafka, Mailpit and evidence storage,
plus bootstrap jobs. Current readiness includes database, Redis and Kafka health.
That deployment gating is distinct from per-operation behavior: authorization
snapshot cache failures can fall back to fresh MySQL, and committed outbox records
can await Kafka recovery. Internal authorization fails closed if current SQL
authority cannot be established. Live collector recovery and production
TLS/RBAC/retention/backup/alert delivery remain the previously deferred work.

## Configuration sources

- [Workspace Compose services](../../docker-compose.yaml)
- [Shared Elastic telemetry services](../../docker-compose.yaml), [Filebeat](../docker/observability/filebeat.yml), [APM](../docker/observability/apm-server.yml)
- [Shared metrics services](../../docker-compose.yaml), [Prometheus scrape configuration](../docker/metrics/prometheus.yml), [private management listener](../src/main/resources/application-metrics.properties)
- [Shared Grafana service](../../docker/compose/grafana.yml), [datasource provisioning](../docker/metrics/grafana/provisioning/datasources/prometheus.yaml)
- [Observability implementation record](UNIDOCS_AUTH_OBSERVABILITY.md), [security audit contract](observability/login-audit.md)
