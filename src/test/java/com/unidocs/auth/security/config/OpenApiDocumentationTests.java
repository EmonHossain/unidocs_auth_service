package com.unidocs.auth.security.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import com.unidocs.auth.shared.config.OpenApiConfiguration;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@TestPropertySource(properties = {"springdoc.api-docs.enabled=true", "springdoc.swagger-ui.enabled=true"})
@Import(OpenApiConfiguration.class)
@org.springframework.boot.context.properties.EnableConfigurationProperties({
        org.springdoc.core.properties.SwaggerUiConfigProperties.class,
        org.springdoc.core.properties.SwaggerUiOAuthProperties.class,
        org.springdoc.core.properties.SpringDocConfigProperties.class})
@ImportAutoConfiguration({org.springdoc.core.configuration.SpringDocConfiguration.class,
        org.springdoc.core.configuration.SpringDocSecurityConfiguration.class,
        org.springdoc.webmvc.core.configuration.SpringDocWebMvcConfiguration.class,
        org.springdoc.webmvc.ui.SwaggerConfig.class})
class OpenApiDocumentationTests extends SecurityConfigurationTests {
    @Override @Test
    void documentationIsClosedByDefault() throws Exception {
        mvc.perform(get("/v3/api-docs")).andExpect(status().isOk())
                .andExpect(jsonPath("$.info.title").value("UniDocs IAM & Authentication API"))
                .andExpect(jsonPath("$.components.securitySchemes.bearerAuth.scheme").value("bearer"))
                .andExpect(jsonPath("$.paths['/api/v1/registrations'].post.responses['201']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/auth/logout'].post.responses['204']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/auth/login'].post.security").isEmpty())
                .andExpect(jsonPath("$.paths['/api/v1/me'].get.security[0].bearerAuth").isArray())
                .andExpect(jsonPath("$.paths['/api/v1/internal/authorization/account']").doesNotExist())
                .andExpect(jsonPath("$.components.schemas.LoginRequest.properties.password.writeOnly").value(true))
                .andExpect(jsonPath("$.paths['/api/v1/me'].get.responses['403'].content['application/problem+json']").exists());
        mvc.perform(get("/swagger-ui.html")).andExpect(status().is3xxRedirection());
        mvc.perform(get("/swagger-ui/index.html")).andExpect(status().isOk());
    }

    @Override @Test
    void documentationCannotBeAccessedWhenDisabled() throws Exception {
        mvc.perform(get("/v3/api-docs/swagger-config")).andExpect(status().isOk())
                .andExpect(jsonPath("$.persistAuthorization").value(false));
    }
}
