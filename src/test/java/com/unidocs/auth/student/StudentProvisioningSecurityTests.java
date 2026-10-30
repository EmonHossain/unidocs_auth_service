package com.unidocs.auth.student;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import com.unidocs.auth.authorization.application.OperationAuthorizationFailure;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class StudentProvisioningSecurityTests {
    @Configuration @EnableMethodSecurity static class Security { }
    private final JdbcTemplate jdbc=mock(JdbcTemplate.class);
    private final Instant now=Instant.parse("2026-10-16T12:00:00Z");
    private AnnotationConfigApplicationContext context;
    private StudentProvisioningService service;
    @BeforeEach void setup() {
        SecurityContextHolder.clearContext();context=new AnnotationConfigApplicationContext();context.register(Security.class);
        context.registerBean(StudentProvisioningService.class,()->new StudentProvisioningService(jdbc,Clock.fixed(now,ZoneOffset.UTC),mock(OutboxRepository.class)));
        context.refresh();service=context.getBean(StudentProvisioningService.class);
    }
    @AfterEach void close() { SecurityContextHolder.clearContext();context.close(); }
    @Test void ordinaryUserCannotPollOrAcknowledgeProvisioning() {
        JwtAuthenticationToken user=token("ordinary-user",false,now.plusSeconds(60));SecurityContextHolder.getContext().setAuthentication(user);
        assertThatThrownBy(()->service.pending(user,null,10)).isInstanceOf(AccessDeniedException.class);verifyNoInteractions(jdbc);
    }
    @Test void anotherScopedServiceCannotProvisionStudentWorkspaces() {
        JwtAuthenticationToken other=token("other-service",true,now.plusSeconds(60));SecurityContextHolder.getContext().setAuthentication(other);
        assertThatThrownBy(()->service.pending(other,null,10)).isInstanceOf(OperationAuthorizationFailure.class);verifyNoInteractions(jdbc);
    }
    @Test void expiredDocumentServiceCannotReadCommittedIntents() {
        JwtAuthenticationToken expired=token("document-service",true,now);SecurityContextHolder.getContext().setAuthentication(expired);
        assertThatThrownBy(()->service.pending(expired,null,10)).isInstanceOf(OperationAuthorizationFailure.class);verifyNoInteractions(jdbc);
    }
    @Test void callerCannotSubstituteAnotherAuthenticationObject() {
        JwtAuthenticationToken current=token("document-service",true,now.plusSeconds(60));SecurityContextHolder.getContext().setAuthentication(current);
        assertThatThrownBy(()->service.pending(token("document-service",true,now.plusSeconds(60)),null,10)).isInstanceOf(OperationAuthorizationFailure.class);verifyNoInteractions(jdbc);
    }
    @Test void allowlistedCurrentServiceCanReadBoundedIntents() {
        JwtAuthenticationToken current=token("document-service",true,now.plusSeconds(60));SecurityContextHolder.getContext().setAuthentication(current);
        assertThat(service.pending(current,null,10)).isEmpty();
    }
    private JwtAuthenticationToken token(String service,boolean scoped,Instant expires) {
        Jwt jwt=Jwt.withTokenValue("synthetic-"+service).header("alg","RS256").subject(service).claim("azp",service).expiresAt(expires).build();
        return new JwtAuthenticationToken(jwt,scoped?List.of(new SimpleGrantedAuthority("SCOPE_iam.authorization.read")):List.of());
    }
}
