# syntax=docker/dockerfile:1
FROM eclipse-temurin:25-jdk-noble AS secrets-build
WORKDIR /build
COPY docker/PrepareLocalSecrets.java .
RUN javac -d classes PrepareLocalSecrets.java

FROM eclipse-temurin:25-jdk-noble AS build
WORKDIR /build
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN sed -i 's/\r$//' mvnw
RUN apt-get update && apt-get install --yes --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY src/ src/
# Integration tests run with host Docker in the normal Maven/CI lifecycle.
RUN --mount=type=cache,target=/root/.m2 bash ./mvnw --batch-mode --no-transfer-progress -DskipTests package

# Persistent local test tools share Compose infrastructure without a Docker socket.
FROM build AS test-runtime
RUN --mount=type=cache,target=/root/.m2 mkdir -p /opt/maven-cache && cp -a /root/.m2/. /opt/maven-cache/
RUN mkdir -p /app
COPY --from=build /build/target/auth-service-0.0.1-SNAPSHOT.jar /app/app.jar
COPY --chmod=0755 docker/application-entrypoint.sh /app/application-entrypoint.sh
COPY --chmod=0755 docker/test-service-entrypoint.sh /app/test-service-entrypoint.sh
WORKDIR /workspace
ENV TZ=UTC
ENTRYPOINT ["/bin/bash", "/app/test-service-entrypoint.sh"]

FROM eclipse-temurin:25-jre-noble AS runtime-base
RUN apt-get update \
    && apt-get install --yes --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 auth \
    && useradd --uid 10001 --gid auth --no-create-home --home-dir /app auth
RUN mkdir -p /var/log/unidocs && chown 10001:10001 /var/log/unidocs
WORKDIR /app
ENV TZ=UTC
USER 10001:10001

FROM runtime-base AS secrets-init
USER root
COPY --from=secrets-build /build/classes/ /app/setup/
ENTRYPOINT ["/bin/sh", "-c", "java -cp /app/setup PrepareLocalSecrets /secrets/database /secrets/application /secrets/evidence && chown -R 10001:10001 /secrets/application /secrets/evidence"]

FROM runtime-base AS runtime
COPY --from=build --chown=10001:10001 /build/target/auth-service-0.0.1-SNAPSHOT.jar /app/app.jar
COPY --from=build --chown=10001:10001 /build/target/auth-service-0.0.1-SNAPSHOT-spicedb-schema-operator.jar /app/spicedb-schema-operator.jar
COPY --from=build --chown=10001:10001 /build/target/auth-service-0.0.1-SNAPSHOT-spicedb-api-gateway.jar /app/spicedb-api-gateway.jar
COPY --chown=10001:10001 --chmod=0755 docker/application-entrypoint.sh /app/application-entrypoint.sh
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=90s --retries=5 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8080/actuator/health/readiness || exit 1
ENTRYPOINT ["/app/application-entrypoint.sh"]
