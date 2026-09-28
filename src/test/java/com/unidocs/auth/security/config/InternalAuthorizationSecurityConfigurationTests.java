package com.unidocs.auth.security.config;

import java.time.Clock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import tools.jackson.databind.json.JsonMapper;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringJUnitWebConfig(InternalAuthorizationSecurityConfigurationTests.Config.class)
@TestPropertySource(properties = {"auth.jwt.issuer=user-issuer", "auth.jwt.audience=user-api",
        "auth.internal-authorization.enabled=true", "auth.internal-authorization.issuer=https://identity.example",
        "auth.internal-authorization.audience=iam-internal", "auth.internal-authorization.jwk-set-uri=https://identity.example/jwks",
        "auth.internal-authorization.service-subjects=document-service"})
class InternalAuthorizationSecurityConfigurationTests {
    @Autowired WebApplicationContext context;
    private MockMvc mvc;
    @BeforeEach void configure() { mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build(); }
    @Test void missingServiceTokenIs401() throws Exception {
        mvc.perform(post("/api/v1/internal/authorization/organization").header("X-User-Id", "attacker")
                .header("X-Delegated-Authorization", "Bearer user-token")).andExpect(status().isUnauthorized());
    }
    @Test void malformedTokenIs401() throws Exception {
        mvc.perform(post("/api/v1/internal/authorization/organization").header("Authorization", "Bearer malformed"))
                .andExpect(status().isUnauthorized());
    }
    @Test void missingScopeIs403() throws Exception {
        mvc.perform(post("/api/v1/internal/authorization/organization").with(jwt().authorities()))
                .andExpect(status().isForbidden());
    }
    @Test void scopedServiceCanReachEndpoint() throws Exception {
        mvc.perform(post("/api/v1/internal/authorization/organization").with(jwt().authorities(
                new SimpleGrantedAuthority("SCOPE_iam.authorization.read")))).andExpect(status().isOk());
    }
    @Test void otherInternalPathsRemainForbidden() throws Exception {
        mvc.perform(post("/api/v1/internal/other").with(jwt().authorities(
                new SimpleGrantedAuthority("SCOPE_iam.authorization.read")))).andExpect(status().isForbidden());
    }
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"account", "group"})
    void scopedServiceCanReachAccountAndGroup(String scope) throws Exception {
        mvc.perform(post("/api/v1/internal/authorization/" + scope).with(jwt().authorities(
                new SimpleGrantedAuthority("SCOPE_iam.authorization.read")))).andExpect(status().isOk());
    }
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"account", "group"})
    void accountAndGroupRequireScope(String scope) throws Exception {
        mvc.perform(post("/api/v1/internal/authorization/" + scope).with(jwt().authorities()))
                .andExpect(status().isForbidden());
    }
    @Configuration @EnableWebSecurity @EnableWebMvc
    @Import({InternalAuthorizationSecurityConfiguration.class, SecurityProblemWriter.class, Endpoint.class})
    static class Config {
        @Bean Clock clock() { return Clock.systemUTC(); }
        @Bean JsonMapper mapper() { return JsonMapper.builder().build(); }
    }
    @RestController static class Endpoint {
        @PostMapping({"/api/v1/internal/authorization/organization", "/api/v1/internal/authorization/account",
                "/api/v1/internal/authorization/group"}) String check() { return "ok"; }
    }
}

