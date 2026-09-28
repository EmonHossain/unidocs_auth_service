package com.unidocs.auth.security.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringJUnitWebConfig(InternalAuthorizationSecurityConfigurationTests.Config.class)
@TestPropertySource(properties = {"auth.jwt.issuer=user-issuer", "auth.jwt.audience=user-api"})
class InternalAuthorizationDisabledTests {
    @Autowired WebApplicationContext context;
    @Test void disabledEndpointDeniesEvenAuthenticatedToken() throws Exception {
        MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build()
                .perform(post("/api/v1/internal/authorization/organization").with(jwt()))
                .andExpect(status().isForbidden());
    }
    @Test void disabledEndpointDeniesAnonymous() throws Exception {
        MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build()
                .perform(post("/api/v1/internal/authorization/organization")).andExpect(status().isUnauthorized());
    }
}
