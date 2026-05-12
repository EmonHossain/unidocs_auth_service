package com.unidocs.auth.shared.config;

import java.util.List;
import java.util.Set;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
public class OpenApiConfiguration {
    private static final String BEARER = "bearerAuth";
    private static final Set<String> PUBLIC_OPERATIONS = Set.of(
            "AuthenticationController.login", "AuthenticationController.loginAccount",
            "AuthenticationController.refresh", "AuthenticationController.jwks",
            "RegistrationController.register", "RegistrationController.verify", "RegistrationController.complete",
            "EmailRecoveryController.forgot", "EmailRecoveryController.reset",
            "EmployeeRecoveryController.request", "EmployeeRecoveryController.reset",
            "EmployeeController.login", "AccountLifecycleController.restore");

    @Bean
    OpenAPI authOpenApi() {
        Schema<?> problem = new Schema<>().type("object")
                .addProperty("type", new Schema<>().type("string").format("uri"))
                .addProperty("title", new Schema<>().type("string"))
                .addProperty("status", new Schema<>().type("integer").format("int32"))
                .addProperty("detail", new Schema<>().type("string"))
                .addProperty("instance", new Schema<>().type("string").format("uri"))
                .addProperty("requestId", new Schema<>().type("string")
                        .description("Correlation identifier for support and diagnostics."));
        return new OpenAPI().info(new Info().title("UniDocs IAM & Authentication API").version("v1")
                .description("Identity, registration, sessions, linked accounts, organizations and groups. "
                        + "Register, verify, then complete provisioning before login. Use the returned accessToken "
                        + "in Authorize. Account grants and current memberships are checked server-side; "
                        + "a preferred account is only a navigation preference. Lists use cursor pagination where available. "
                        + "Errors use application/problem+json with a requestId. Try it out executes real requests."))
                .components(new Components().addSchemas("ApiProblem", problem)
                        .addSecuritySchemes(BEARER, new SecurityScheme().type(SecurityScheme.Type.HTTP)
                                .scheme("bearer").bearerFormat("JWT")
                                .description("Paste the access token returned by login, without the Bearer prefix.")));
    }

    @Bean
    OperationCustomizer authOperationDocumentation() {
        return (operation, handler) -> {
            String key = handler.getBeanType().getSimpleName() + "." + handler.getMethod().getName();
            boolean authenticated = !PUBLIC_OPERATIONS.contains(key);
            operation.setOperationId(handler.getBeanType().getSimpleName().replace("Controller", "")
                    + "_" + handler.getMethod().getName());
            operation.setSecurity(authenticated ? List.of(new SecurityRequirement().addList(BEARER)) : List.of());
            if (handler.getBeanType().getSimpleName().equals("AuthenticationController")
                    && Set.of("login", "loginAccount", "refresh", "logout", "logoutAll").contains(handler.getMethod().getName())) {
                operation.addParametersItem(new io.swagger.v3.oas.models.parameters.Parameter()
                        .name("X-Auth-Transport").in("header").required(false)
                        .description("Omit for JSON refresh tokens. 'cookie' requires an explicitly allowed Origin; "
                                + "refresh then uses a Secure HttpOnly cookie with no request body.")
                        .schema(new io.swagger.v3.oas.models.media.StringSchema()._enum(List.of("cookie"))));
            }
            addProblem(operation, "400", "Invalid request, malformed input or failed validation.");
            if (authenticated) {
                addProblem(operation, "401", "Missing, invalid or expired authentication.");
                addProblem(operation, "403", "Current session, account grant or membership does not permit this action.");
            } else if (!handler.getMethod().getName().equals("jwks")) {
                addProblem(operation, "401", "Invalid credentials or verification proof, where required.");
            }
            addProblem(operation, "500", "Unexpected server failure; use requestId for diagnostics.");
            return operation;
        };
    }

    private static void addProblem(io.swagger.v3.oas.models.Operation operation, String status, String description) {
        if (!operation.getResponses().containsKey(status)) {
            operation.getResponses().addApiResponse(status, new ApiResponse().description(description)
                    .content(new Content().addMediaType("application/problem+json", new MediaType()
                            .schema(new Schema<>().$ref("#/components/schemas/ApiProblem")))));
        }
    }
}

