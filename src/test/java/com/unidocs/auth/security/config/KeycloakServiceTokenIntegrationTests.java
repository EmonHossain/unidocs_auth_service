package com.unidocs.auth.security.config;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Explicit acceptance suite against the reusable Compose Keycloak, not an emulated issuer. */
@EnabledIfEnvironmentVariable(named = "KEYCLOAK_ACCEPTANCE", matches = "true")
class KeycloakServiceTokenIntegrationTests {
    private static final String ISSUER = "https://keycloak:8443/realms/unidocs-services";

    @Test
    void actualClientCredentialsTokenSatisfiesAuthContract() throws Exception {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", "document-service");
        form.add("client_secret", Files.readString(Path.of(".keycloak/document-client-secret")).trim());
        form.add("scope", "iam.authorization.read");
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        Map<?, ?> response = new RestTemplate().postForObject(ISSUER + "/protocol/openid-connect/token",
                new HttpEntity<>(form, headers), Map.class);
        if (response == null || !(response.get("access_token") instanceof String token)) {
            throw new IllegalStateException("Keycloak did not return an access token.");
        }
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(ISSUER + "/protocol/openid-connect/certs").build();
        decoder.setJwtValidator(validator(ISSUER, "urn:unidocs:iam-internal", "document-service"));
        Jwt jwt = decoder.decode(token);
        assertThat(jwt.getSubject()).isEqualTo("document-service");
        assertThat(jwt.hasClaim("sid")).isFalse();
        assertThat(jwt.getClaimAsString("scope").split(" ")).contains("iam.authorization.read");
        assertThat(jwt.getExpiresAt()).isBeforeOrEqualTo(jwt.getIssuedAt().plusSeconds(300));
        assertThat(validator("wrong-issuer", "urn:unidocs:iam-internal", "document-service").validate(jwt).hasErrors()).isTrue();
        assertThat(validator(ISSUER, "wrong-audience", "document-service").validate(jwt).hasErrors()).isTrue();
        assertThat(validator(ISSUER, "urn:unidocs:iam-internal", "unknown-service").validate(jwt).hasErrors()).isTrue();
        int signature = token.lastIndexOf('.') + 1;
        String altered = token.substring(0, signature) + (token.charAt(signature) == 'A' ? "B" : "A")
                + token.substring(signature + 1);
        assertThatThrownBy(() -> decoder.decode(altered)).isInstanceOf(JwtException.class);
    }

    private static InternalServiceTokenValidator validator(String issuer, String audience, String subject) {
        return new InternalServiceTokenValidator(new InternalAuthorizationProperties(true, issuer, audience,
                ISSUER + "/protocol/openid-connect/certs", Set.of(subject)), Clock.systemUTC());
    }
}
