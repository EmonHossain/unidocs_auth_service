package com.unidocs.auth.security.config;

import com.unidocs.auth.shared.config.ApiVersionProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
@org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
@EnableConfigurationProperties(ApiVersionProperties.class)
public class SecurityConfiguration {
    @Bean
    VerifiedPrincipal verifiedPrincipal() { return new VerifiedPrincipal(); }
    @Bean
    @org.springframework.core.annotation.Order(2)
    SecurityFilterChain securityFilterChain(HttpSecurity http, SecurityProblemWriter problems, ApiVersionProperties api,
            org.springframework.core.env.Environment environment,
            @org.springframework.beans.factory.annotation.Qualifier("jwtDecoder") org.springframework.security.oauth2.jwt.JwtDecoder productDecoder) throws Exception {
        boolean documentationEnabled = environment.getProperty("springdoc.api-docs.enabled", Boolean.class, false);
        return http
                .addFilterAfter(new AuthenticatedDiagnosticContextFilter(),
                        org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter.class)
                .cors(org.springframework.security.config.Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.GET, "/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs", "/v3/api-docs/**", "/v3/api-docs.yaml")
                        .access((authentication, context) -> new org.springframework.security.authorization.AuthorizationDecision(documentationEnabled))
                        .requestMatchers(HttpMethod.GET, "/actuator/health", "/actuator/health/liveness",
                                "/actuator/health/readiness", "/livez", "/readyz", "/.well-known/jwks.json").permitAll()
                        .requestMatchers(HttpMethod.POST, api.path("/registrations"),
                                api.path("/registrations/{id}/verify"), api.path("/registrations/{id}/complete"),
                                api.path("/auth/forgot-password"), api.path("/auth/reset-password"),
                                api.path("/auth/employee-forgot-password"), api.path("/auth/employee-reset-password"),
                                api.path("/auth/employee-login"), api.path("/auth/login"), api.path("/auth/refresh"), api.path("/auth/accounts/{accountId}/login"),
                                api.path("/accounts/{accountId}/restore")).permitAll()
                        .requestMatchers(HttpMethod.GET,api.path("/me/account-removal/options"),api.path("/me/account-removal-requests"),
                                api.path("/me/account-notices"),api.path("/organizations/{org}/account-removal-requests")).authenticated()
                        .requestMatchers(HttpMethod.POST,api.path("/me/account-removals"),
                                api.path("/organizations/{org}/members/{membership}/account-actions"),
                                api.path("/organizations/{org}/account-removal-requests/{requestId}/review")).authenticated()
                        .requestMatchers(HttpMethod.GET, api.path("/me"), api.path("/me/accounts"),
                                api.path("/me/organizations"), api.path("/organizations/{id}")).authenticated()
                        .requestMatchers(HttpMethod.GET, api.path("/organizations/{org}/password-recovery-requests")).authenticated()
                        .requestMatchers(HttpMethod.POST, api.path("/organizations/{org}/password-recovery-requests/{request}/reset")).authenticated()
                        .requestMatchers(HttpMethod.POST, api.path("/organizations/{org}/employees"), api.path("/organizations/{org}/employees/{account}/temporary-credentials")).authenticated()
                        .requestMatchers(api.path("/institutes/{org}/student-admissions"), api.path("/institutes/{org}/student-admissions/{id}"),
                                api.path("/institutes/{org}/student-admissions/{id}/verify"), api.path("/institutes/{org}/student-admissions/{id}/review"),
                                api.path("/institutes/{org}/student-admissions/{id}/evidence"), api.path("/institutes/{org}/student-email-domains"), api.path("/institutes/{org}/curators")).authenticated()
                        .requestMatchers(HttpMethod.POST, api.path("/organizations")).authenticated()
                        .requestMatchers(HttpMethod.PUT,api.path("/organizations/{organizationId}/groups/{groupId}/rules"),
                                api.path("/organizations/{organizationId}/course-enrollment")).authenticated()
                        .requestMatchers(HttpMethod.GET,api.path("/organizations/{organizationId}/discoverable-groups"),
                                api.path("/organizations/{organizationId}/groups/{groupId}/rules"),
                                api.path("/organizations/{organizationId}/discoverable-groups/{groupId}"),api.path("/organizations/{organizationId}/academic-semesters"),
                                api.path("/organizations/{organizationId}/me/course-enrollment"),api.path("/organizations/{organizationId}/me/group-invitations")).authenticated()
                        .requestMatchers(HttpMethod.POST,api.path("/organizations/{organizationId}/academic-semesters"),
                                api.path("/organizations/{organizationId}/groups/{groupId}/join"),api.path("/organizations/{organizationId}/groups/{groupId}/invitations"),
                                api.path("/organizations/{organizationId}/groups/{groupId}/invitations/{invitationId}/accept"),
                                api.path("/organizations/{organizationId}/groups/{groupId}/invitations/{invitationId}/revoke")).authenticated()
                        .requestMatchers(HttpMethod.POST, api.path("/organizations/{organizationId}/groups")).authenticated()
                        .requestMatchers(HttpMethod.POST, api.path("/organizations/{organizationId}/groups/{groupId}/memberships"),
                                api.path("/organizations/{organizationId}/groups/{groupId}/memberships/{membershipId}/revoke")).authenticated()
                        .requestMatchers(HttpMethod.POST, api.path("/organizations/{organizationId}/groups/{groupId}/join-requests"),
                                api.path("/organizations/{organizationId}/groups/{groupId}/join-requests/{requestId}/review"),
                                api.path("/organizations/{organizationId}/groups/{groupId}/join-requests/{requestId}/cancel")).authenticated()
                        .requestMatchers(HttpMethod.GET, api.path("/organizations/{organizationId}/groups/{groupId}/join-requests"),
                                api.path("/organizations/{organizationId}/me/group-join-requests")).authenticated()
                        .requestMatchers(HttpMethod.GET, api.path("/organizations/{organizationId}/groups/{groupId}/memberships"),
                                api.path("/organizations/{organizationId}/me/group-memberships")).authenticated()
                        .requestMatchers(HttpMethod.GET, api.path("/organizations/{organizationId}/groups"),
                                api.path("/organizations/{organizationId}/groups/{groupId}")).authenticated()
                        .requestMatchers(HttpMethod.POST, api.path("/organizations/{organizationId}/invitations"),
                                api.path("/organizations/{organizationId}/invitations/{id}/accept"),
                                api.path("/organizations/{organizationId}/invitations/{id}/provision-account")).authenticated()
                        .requestMatchers(HttpMethod.PUT,api.path("/organizations/{organization}/professional/responsibilities"),api.path("/organizations/{organization}/professional/restrictions")).authenticated()
                        .requestMatchers(HttpMethod.GET,api.path("/me/professional-notices")).authenticated()
                        .requestMatchers(HttpMethod.GET,api.path("/organizations/{organization}/professional/members"),
                                api.path("/organizations/{organization}/professional/responsibilities"),api.path("/organizations/{organization}/professional/restrictions"),
                                api.path("/organizations/{organization}/professional/projection-status"),
                                api.path("/organizations/{organization}/professional/access-catalog"),
                                api.path("/organizations/{organization}/professional/access-preview"),
                                api.path("/organizations/{organization}/professional/audit")).authenticated()
                        .requestMatchers(HttpMethod.POST, api.path("/auth/logout"), api.path("/auth/logout-all")).authenticated()
                        .requestMatchers(HttpMethod.POST, api.path("/accounts/{accountId}/challenges"),
                                api.path("/accounts/{accountId}/challenges/{id}/complete")).authenticated()
                        .requestMatchers(HttpMethod.PUT, api.path("/me/preferred-account")).authenticated()
                        .requestMatchers(HttpMethod.POST,api.path("/developer/professional-reconciliations/{organization}")).authenticated()
                        .requestMatchers(HttpMethod.POST,api.path("/developer/institutes/{organization}/student-admin"),
                                api.path("/developer/institutes/{organization}/staff-reconciliations"),
                                api.path("/developer/institutes/{organization}/enforcement-proofs"),api.path("/developer/institutes/{organization}/enforcement-decisions")).authenticated()
                        .requestMatchers(HttpMethod.POST,api.path("/institutes/{organization}/workspace/semesters"),api.path("/institutes/{organization}/workspace/courses"),
                                api.path("/institutes/{organization}/workspace/courses/{course}/join"),api.path("/institutes/{organization}/workspace/study-groups"),
                                api.path("/institutes/{organization}/workspace/study-groups/{group}/invitations"),api.path("/institutes/{organization}/workspace/study-invitations/{id}/respond"),
                                api.path("/institutes/{organization}/workspace/study-groups/{group}/invitations/{id}/revoke"),
                                api.path("/institutes/{organization}/workspace/study-groups/{group}/deletion"),api.path("/institutes/{organization}/workspace/study-groups/{group}/leave"),
                                api.path("/institutes/{organization}/workspace/reports"),api.path("/institutes/{organization}/workspace/report-evidence")).authenticated()
                        .requestMatchers(HttpMethod.PUT,api.path("/institutes/{organization}/workspace/courses/{course}"),api.path("/institutes/{organization}/workspace/reports/{id}/review")).authenticated()
                        .requestMatchers(HttpMethod.GET,api.path("/institutes/{organization}/workspace/courses"),api.path("/institutes/{organization}/workspace/courses/{course}/study-groups"),
                                api.path("/institutes/{organization}/workspace/semesters"),
                                api.path("/institutes/{organization}/workspace/study-invitations"),api.path("/institutes/{organization}/workspace/study-groups/{group}/members"),
                                api.path("/institutes/{organization}/workspace/reports"),api.path("/institutes/{organization}/workspace/reports/{id}"),
                                api.path("/institutes/{organization}/workspace/reports/{report}/evidence/{evidence}"),api.path("/institutes/{organization}/workspace/notices")).authenticated()
                        .requestMatchers(HttpMethod.POST, api.path("/developer/catalog"), api.path("/developer/roles"),
                                api.path("/personal/groups"), api.path("/personal/groups/{id}/invitations"),
                                api.path("/personal/groups/invitations/{id}/accept"), api.path("/personal/groups/invitations/{id}/decline"),
                                api.path("/personal/groups/{groupId}/invitations/{id}/revoke"), api.path("/personal/groups/{groupId}/leave"),
                                api.path("/personal/groups/{groupId}/deletion"), api.path("/personal/groups/{groupId}/deletion/cancel")).authenticated()
                        .requestMatchers(HttpMethod.PUT, api.path("/developer/roles/{id}"), api.path("/developer/categories/{category}"),
                                api.path("/developer/student-responsibilities/{responsibility}"),
                                api.path("/developer/baselines/{category}"), api.path("/developer/relationships/{relationship}"),
                                api.path("/developer/operations/{id}/policy")).authenticated()
                        .requestMatchers(HttpMethod.GET, api.path("/personal/groups"), api.path("/personal/groups/{id}"),
                                api.path("/personal/groups/invitations"), api.path("/personal/groups/{groupId}/invitations"),
                                api.path("/personal/groups/{groupId}/members")).authenticated()
                        .requestMatchers(HttpMethod.DELETE, api.path("/personal/groups/{groupId}/members/{recipientAccountId}")).authenticated()
                        .anyRequest().denyAll())
                .oauth2ResourceServer(resource -> resource
                        .jwt(jwt -> jwt.decoder(productDecoder).jwtAuthenticationConverter(token ->
                                new org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken(token,
                                        java.util.List.of())))
                        .authenticationEntryPoint((request, response, exception) -> problems.write(request,
                                response, HttpStatus.UNAUTHORIZED, "Authentication is required.")))
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint((request, response, exception) -> problems.write(request,
                                response, HttpStatus.UNAUTHORIZED, "Authentication is required."))
                        .accessDeniedHandler((request, response, exception) -> problems.write(request,
                                response, HttpStatus.FORBIDDEN, "Access is forbidden.")))
                .build();
    }

    @Bean
    UserDetailsService userDetailsService() {
        // Prevent Boot from creating a generated development user/password.
        return username -> { throw new UsernameNotFoundException("Use the IAM login endpoint."); };
    }
}

