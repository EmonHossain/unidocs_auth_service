#!/bin/sh
set -eu
umask 077
case "${SPRING_PROFILES_ACTIVE:-}" in
    prod|prod,*)
        : "${SPRING_MAIL_HOST:?Set AUTH_PROD_SMTP_HOST in Auth .env}"
        : "${SPRING_MAIL_USERNAME:?Set AUTH_PROD_SMTP_USERNAME in Auth .env}"
        : "${SPRING_MAIL_PASSWORD:?Set AUTH_PROD_SMTP_PASSWORD in Auth .env}"
        : "${AUTH_TLS_STORE_PASSWORD:?Run prepare-local.ps1 -LocalProduction}"
        if [ "$SPRING_MAIL_HOST" = mailpit ]; then
            echo 'Production SMTP must use an external provider.' >&2
            exit 1
        fi
        ;;
esac
# Java prints JAVA_TOOL_OPTIONS at startup. Keep the trust-store password in
# a private argument file instead of exposing it in application console logs.
if [ -f /run/secrets/keycloak/auth-truststore.p12 ]; then
    trust_options="$(mktemp /tmp/auth-java-options.XXXXXX)"
    trust_password="$(printf '%s' "${KEYCLOAK_TRUSTSTORE_PASSWORD:-}" | sed 's/\\/\\\\/g; s/"/\\"/g')"
    printf '%s\n' '-Djavax.net.ssl.trustStore=/run/secrets/keycloak/auth-truststore.p12' \
        "\"-Djavax.net.ssl.trustStorePassword=$trust_password\"" \
        '-Djavax.net.ssl.trustStoreType=PKCS12' > "$trust_options"
    exec java "@$trust_options" -XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError -jar /app/app.jar "$@"
fi
exec java -XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError -jar /app/app.jar "$@"
