package com.unidocs.auth.security.config;

import java.util.Set;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "auth.management.scrape.enabled", havingValue = "true")
@EnableConfigurationProperties(ManagementScrapeProperties.class)
public class ManagementScrapeSecurityConfiguration {
    @Bean
    @Order(1)
    SecurityFilterChain managementScrapeSecurityFilterChain(HttpSecurity http,
            ManagementScrapeProperties properties, SecurityProblemWriter problems, Environment environment) throws Exception {
        validateListener(environment, properties);
        int configuredPort = environment.getRequiredProperty("management.server.port", Integer.class);
        return http
                .securityMatcher(request -> request.getLocalPort() == environment.getProperty(
                        "local.management.port", Integer.class, configuredPort))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .addFilterBefore(new ManagementScrapeAuthenticationFilter(properties), AnonymousAuthenticationFilter.class)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.GET, "/actuator/health", "/actuator/health/liveness",
                                "/actuator/health/readiness").permitAll()
                        .requestMatchers(HttpMethod.GET, "/actuator/prometheus").hasRole("METRICS_SCRAPER")
                        .anyRequest().denyAll())
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint((request, response, failure) ->
                                problems.write(request, response, HttpStatus.UNAUTHORIZED, "Authentication is required."))
                        .accessDeniedHandler((request, response, failure) ->
                                problems.write(request, response, HttpStatus.FORBIDDEN, "Access is forbidden.")))
                .build();
    }

    static void validateListener(Environment environment) {
        validateListener(environment, new ManagementScrapeProperties(true,
                environment.getProperty("auth.management.scrape.token", ""),
                environment.getProperty("auth.management.scrape.allow-private-network", Boolean.class, false)));
    }

    static void validateListener(Environment environment, ManagementScrapeProperties properties) {
        Integer managementPort = environment.getProperty("management.server.port", Integer.class);
        int applicationPort = environment.getProperty("server.port", Integer.class, 8080);
        String address = environment.getProperty("management.server.address", "");
        Set<String> profiles = Set.of(environment.getActiveProfiles());
        boolean privateListenerAllowed = properties.allowPrivateNetwork() && address.equals("0.0.0.0")
                && (profiles.contains("dev") || profiles.contains("test")) && !profiles.contains("prod");
        if (managementPort == null || managementPort < 1 || managementPort > 65535
                || managementPort == applicationPort
                || (!Set.of("127.0.0.1", "::1", "localhost").contains(address) && !privateListenerAllowed)) {
            throw new IllegalStateException("Management scraping requires a separate loopback listener.");
        }
        if (privateListenerAllowed && (!properties.enabled() || !ManagementScrapeProperties.validToken(properties.token()))) {
            throw new IllegalArgumentException("Private management scraping requires an enabled scraper and valid token.");
        }
    }
}
