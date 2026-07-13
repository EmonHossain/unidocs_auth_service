package com.unidocs.auth;

import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:mysql://127.0.0.1:1/unavailable",
        "spring.data.redis.host=127.0.0.1", "spring.data.redis.port=1",
        "spring.kafka.bootstrap-servers=127.0.0.1:1",
        "spring.mail.host=127.0.0.1", "spring.mail.port=1",
        "registration.student.storage.endpoint=http://127.0.0.1:1",
        "registration.student.storage.create-bucket=true",
        "management.opentelemetry.tracing.export.otlp.endpoint=http://127.0.0.1:1/v1/traces"
})
@AutoConfigureMockMvc
@ActiveProfiles("offline")
class OfflineProfileIntegrationTests {
    @Autowired MockMvc mvc;
    @Autowired ApplicationContext context;

    @Test
    void startsWithoutDatabaseOrSigningKeysAndReportsHealthy() throws Exception {
        assertThat(context.getBeansOfType(DataSource.class)).isEmpty();
        assertThat(context.getBeansOfType(com.unidocs.auth.authentication.application.AuthenticationService.class)).isEmpty();
        assertThat(context.getBeansOfType(com.unidocs.auth.security.jwt.JwtKeyRing.class)).isEmpty();
        mvc.perform(get("/actuator/health"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("UP"));
        mvc.perform(get("/actuator/health/readiness"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void swaggerRemainsAvailableAndDescribesReducedCapability() throws Exception {
        mvc.perform(get("/swagger-ui.html")).andExpect(status().is3xxRedirection());
        mvc.perform(get("/swagger-ui/index.html")).andExpect(status().isOk());
        mvc.perform(get("/v3/api-docs")).andExpect(status().isOk())
                .andExpect(jsonPath("$.info.title").value("UniDocs Auth — Offline"))
                .andExpect(jsonPath("$.info.description").value(
                        "Dependency-free diagnostic mode. Auth APIs are unavailable (503)."));
    }

    @Test
    void authenticationAndProvisioningStayUnavailable() throws Exception {
        mvc.perform(post("/api/v1/auth/login").contentType("application/json")
                        .content("{\"email\":\"missing@example.test\",\"password\":\"test-password-long\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.title").value("Auth offline"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header()
                        .string("Cache-Control", "no-store"))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("accessToken"))));
        mvc.perform(post("/api/v1/registrations").contentType("application/json").content("{}"))
                .andExpect(status().isServiceUnavailable());
        mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("\"keys\""))));
        mvc.perform(post("/api/v1/internal/authorization/account").contentType("application/json").content("{}"))
                .andExpect(status().isServiceUnavailable());
    }
}
