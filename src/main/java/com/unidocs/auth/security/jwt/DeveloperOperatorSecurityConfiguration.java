package com.unidocs.auth.security.jwt;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.unidocs.auth.security.config.SecurityProblemWriter;
import com.unidocs.auth.shared.config.ApiVersionProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

/** Keeps operator tokens out of the product resource-server chain. */
@Configuration(proxyBeanMethods = false)
@org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(name="auth.developer.operator.enabled",havingValue="true")
public class DeveloperOperatorSecurityConfiguration {
    @Bean("developerOperatorJwtDecoder")
    JwtDecoder developerOperatorJwtDecoder(JwtKeyRing keys,Clock clock,@Value("${auth.jwt.issuer}") String issuer,
            @Value("${auth.developer.jwt.audience:urn:unidocs:developer}") String audience) {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256,
                new ImmutableJWKSet<>(keys.verificationKeys())));
        processor.setJWTClaimsSetVerifier((claims,context)->{ });
        NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        decoder.setJwtValidator(jwt->{
            try {
                UUID.fromString(jwt.getSubject()); UUID.fromString(jwt.getClaimAsString("sid"));
                Instant now=clock.instant(); Instant issued=jwt.getIssuedAt(); Instant expiry=jwt.getExpiresAt();
                if (!(jwt.getHeaders().get("kid") instanceof String kid) || kid.isBlank()
                        || !issuer.equals(jwt.getClaimAsString("iss")) || !jwt.getAudience().contains(audience)
                        || !"DEVELOPER_OPERATOR".equals(jwt.getClaimAsString("realm"))
                        || issued==null || expiry==null || issued.isAfter(now) || !expiry.isAfter(now)
                        || !expiry.isAfter(issued) || expiry.isAfter(issued.plus(DeveloperOperatorTokens.LIFETIME)))
                    throw new IllegalArgumentException();
                return OAuth2TokenValidatorResult.success();
            } catch (RuntimeException failure) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token","Invalid operator token.",null));
            }
        });
        return decoder;
    }

    @Bean
    @Order(1)
    SecurityFilterChain developerOperatorSecurityChain(HttpSecurity http,ApiVersionProperties api,
            SecurityProblemWriter problems,@Qualifier("developerOperatorJwtDecoder") JwtDecoder decoder) throws Exception {
        return http.securityMatcher(api.path("/developer/**"))
                .cors(org.springframework.security.config.Customizer.withDefaults())
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(AbstractHttpConfigurer::disable).csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable).httpBasic(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize->authorize
                        .requestMatchers(org.springframework.http.HttpMethod.POST,api.path("/developer/auth/setup/start"),
                                api.path("/developer/auth/setup/complete"),api.path("/developer/auth/login"),
                                api.path("/developer/auth/refresh"),api.path("/developer/auth/forgot-password"),
                                api.path("/developer/auth/reset-password")).permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(resource->resource.jwt(jwt->jwt.decoder(decoder))
                        .authenticationEntryPoint((request,response,failure)->problems.write(request,response,
                                HttpStatus.UNAUTHORIZED,"Operator authentication is required.")))
                .exceptionHandling(errors->errors
                        .authenticationEntryPoint((request,response,failure)->problems.write(request,response,
                                HttpStatus.UNAUTHORIZED,"Operator authentication is required."))
                        .accessDeniedHandler((request,response,failure)->problems.write(request,response,
                                HttpStatus.FORBIDDEN,"Operator access is forbidden.")))
                .build();
    }
}
