package com.unidocs.auth.offline;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Dependency-free diagnostic mode; no identity or authorization state is created. */
@Configuration(proxyBeanMethods = false)
@Profile("offline")
public class OfflineConfiguration {
    @Bean
    OpenAPI offlineOpenApi() {
        return new OpenAPI().info(new Info().title("UniDocs Auth — Offline")
                .version("v1").description("Dependency-free diagnostic mode. Auth APIs are unavailable (503)."));
    }

    @Bean
    SecurityFilterChain offlineSecurity(HttpSecurity http) throws Exception {
        return http.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(requests -> requests.anyRequest().permitAll()).build();
    }

    @RestController
    @Profile("offline")
    public static class OfflineEndpoints {
        @RequestMapping({"${api.version.base-path:/api/v1}/**", "/.well-known/jwks.json"})
        public ResponseEntity<ProblemDetail> unavailable() {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE,
                    "Auth capabilities are unavailable while the offline profile is active.");
            problem.setTitle("Auth offline");
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).header("Cache-Control", "no-store").body(problem);
        }
    }
}
