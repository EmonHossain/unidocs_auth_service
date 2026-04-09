package com.unidocs.auth.security.config;

import java.time.Clock;
import com.unidocs.auth.shared.config.ApiVersionProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({InternalAuthorizationProperties.class, ApiVersionProperties.class})
public class InternalAuthorizationSecurityConfiguration {
    @Bean
    @Order(2)
    SecurityFilterChain internalAuthorizationSecurityFilterChain(HttpSecurity http,
            InternalAuthorizationProperties properties, ApiVersionProperties api, SecurityProblemWriter problems,
            Clock clock, @Value("${auth.jwt.issuer}") String userIssuer,
            @Value("${auth.jwt.audience}") String userAudience) throws Exception {
        http.securityMatcher(api.path("/internal/**"))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(AbstractHttpConfigurer::disable).csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable).httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint((request, response, failure) -> problems.write(request,
                                response, HttpStatus.UNAUTHORIZED, "Authentication is required."))
                        .accessDeniedHandler((request, response, failure) -> problems.write(request,
                                response, HttpStatus.FORBIDDEN, "Access is forbidden.")));
        if (!properties.enabled()) {
            return http.authorizeHttpRequests(authorize -> authorize.anyRequest().denyAll()).build();
        }
        if (properties.issuer().equals(userIssuer) || properties.audience().equals(userAudience)) {
            throw new IllegalStateException("Service and user token trust must be separate.");
        }
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(2000);
        requestFactory.setReadTimeout(2000);
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(properties.jwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.RS256).restOperations(new RestTemplate(requestFactory)).build();
        decoder.setJwtValidator(new InternalServiceTokenValidator(properties, clock));
        return http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, api.path("/internal/authorization/organization"),
                                api.path("/internal/authorization/account"), api.path("/internal/authorization/group"),
                                api.path("/internal/authorization/operations/evaluate"), api.path("/internal/authorization/operations/validate"),
                                api.path("/internal/authorization/individual-recipient"), api.path("/internal/authorization/personal-group"),
                                api.path("/internal/authorization/professional-recipient"),
                                api.path("/internal/authorization/student-workspaces/pending"),api.path("/internal/authorization/student-workspaces/ready"),
                                api.path("/internal/authorization/student-workspaces/contributors"),
                                api.path("/internal/authorization/personal-groups/closures"),
                                api.path("/internal/authorization/personal-groups/closures/{groupId}/confirm-notices"),
                                api.path("/internal/authorization/personal-groups/closures/{groupId}/state"))
                        .hasAuthority("SCOPE_" + InternalServiceTokenValidator.REQUIRED_SCOPE)
                        .anyRequest().denyAll())
                .oauth2ResourceServer(resource -> resource.jwt(jwt -> jwt.decoder(decoder))
                        .authenticationEntryPoint((request, response, failure) -> problems.write(request,
                                response, HttpStatus.UNAUTHORIZED, "Authentication is required.")))
                .build();
    }
}

