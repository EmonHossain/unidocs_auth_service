package com.unidocs.auth.registration.student;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import com.unidocs.auth.security.config.VerifiedPrincipal;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class StudentAdmissionMethodSecurityTests {
    @Configuration @EnableMethodSecurity static class Security { }
    private final StudentAdmissionService admissions=mock(StudentAdmissionService.class);
    private AnnotationConfigApplicationContext context;
    private StudentAdmissionController controller;
    private final UUID account=UUID.randomUUID(),sid=UUID.randomUUID(),organization=UUID.randomUUID(),admission=UUID.randomUUID();
    @BeforeEach void setup() {
        SecurityContextHolder.clearContext();context=new AnnotationConfigApplicationContext();context.register(Security.class);
        context.registerBean("verifiedPrincipal",VerifiedPrincipal.class,VerifiedPrincipal::new);
        context.registerBean(StudentAdmissionService.class,()->admissions);context.registerBean(StudentAdmissionController.class);context.refresh();
        controller=context.getBean(StudentAdmissionController.class);
    }
    @AfterEach void close() { SecurityContextHolder.clearContext();context.close(); }
    @Test void directUnauthenticatedVerificationCannotReachProvisioning() {
        assertThatThrownBy(()->controller.verify(jwt(),organization,admission,new StudentRequests.Verify(account,"123456"))).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        verifyNoInteractions(admissions);
    }
    @Test void equalClaimsCannotReplaceTheVerifiedPrincipalObject() {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(),List.of()));
        assertThatThrownBy(()->controller.verify(jwt(),organization,admission,new StudentRequests.Verify(account,"123456"))).isInstanceOf(AccessDeniedException.class);
        verifyNoInteractions(admissions);
    }
    @Test void verifiedPrincipalDelegatesOnlyItsOwnSessionIdentity() {
        Jwt jwt=jwt();SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt,List.of()));
        StudentRequests.Verify command=new StudentRequests.Verify(account,"123456");controller.verify(jwt,organization,admission,command);
        verify(admissions).verify(sid,account,organization,admission,command);
    }
    private Jwt jwt() { return Jwt.withTokenValue("synthetic-admission").header("alg","RS256").subject(account.toString()).claim("sid",sid.toString()).expiresAt(Instant.now().plusSeconds(300)).build(); }
}
