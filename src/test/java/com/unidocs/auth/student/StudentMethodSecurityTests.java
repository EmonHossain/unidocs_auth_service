package com.unidocs.auth.student;

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

class StudentMethodSecurityTests {
    @Configuration @EnableMethodSecurity static class Security { }
    private final StudentWorkspaceService service=mock(StudentWorkspaceService.class);
    private final StudentPlatformService platform=mock(StudentPlatformService.class);
    private AnnotationConfigApplicationContext context;
    private StudentWorkspaceController controller;
    private StudentPlatformController developer;
    private final UUID account=UUID.randomUUID(),organization=UUID.randomUUID(),course=UUID.randomUUID(),sid=UUID.randomUUID();
    @BeforeEach void setup() {
        SecurityContextHolder.clearContext();context=new AnnotationConfigApplicationContext();context.register(Security.class);
        context.registerBean("verifiedPrincipal",VerifiedPrincipal.class,VerifiedPrincipal::new);
        context.registerBean(StudentWorkspaceService.class,()->service);context.registerBean(StudentPlatformService.class,()->platform);
        context.registerBean(StudentWorkspaceController.class);context.registerBean(StudentPlatformController.class);context.refresh();
        controller=context.getBean(StudentWorkspaceController.class);developer=context.getBean(StudentPlatformController.class);
    }
    @AfterEach void close() { SecurityContextHolder.clearContext();context.close(); }
    @Test void unauthenticatedDirectProxyCannotJoinOrAppoint() {
        assertThatThrownBy(()->controller.join(jwt(),organization,course,new StudentWorkspaceController.Actor(account))).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        assertThatThrownBy(()->developer.appoint(jwt(),organization,null)).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        verifyNoInteractions(service,platform);
    }
    @Test void equivalentJwtObjectCannotReplaceActualVerifiedPrincipal() {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(),List.of()));
        assertThatThrownBy(()->controller.join(jwt(),organization,course,new StudentWorkspaceController.Actor(account))).isInstanceOf(AccessDeniedException.class);
        verifyNoInteractions(service);
    }
    @Test void verifiedPrincipalCanOnlyDelegateActorSelfJoinToCurrentService() {
        Jwt jwt=jwt();SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt,List.of()));
        controller.join(jwt,organization,course,new StudentWorkspaceController.Actor(account));verify(service).join(jwt,organization,account,course);
    }
    private Jwt jwt() { return Jwt.withTokenValue("synthetic-student-token").header("alg","RS256").subject(account.toString()).claim("sid",sid.toString()).expiresAt(Instant.now().plusSeconds(300)).build(); }
}
