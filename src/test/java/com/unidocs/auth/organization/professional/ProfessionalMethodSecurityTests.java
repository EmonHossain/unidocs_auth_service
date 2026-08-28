package com.unidocs.auth.organization.professional;

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

class ProfessionalMethodSecurityTests {
    @Configuration @EnableMethodSecurity static class Security { }
    private final ProfessionalPolicyService service=mock(ProfessionalPolicyService.class);
    private AnnotationConfigApplicationContext context;
    private ProfessionalPolicyController controller;
    private final UUID account=UUID.randomUUID(),sid=UUID.randomUUID(),organization=UUID.randomUUID();
    @BeforeEach void start() {
        SecurityContextHolder.clearContext();context=new AnnotationConfigApplicationContext();context.register(Security.class);
        context.registerBean("verifiedPrincipal",VerifiedPrincipal.class,VerifiedPrincipal::new);
        context.registerBean(ProfessionalPolicyService.class,()->service);context.registerBean(ProfessionalPolicyController.class);
        context.refresh();controller=context.getBean(ProfessionalPolicyController.class);
    }
    @AfterEach void close() { SecurityContextHolder.clearContext();context.close(); }
    @Test void directProxyCallWithoutAuthenticationNeverReachesPolicyWrites() {
        assertThatThrownBy(()->controller.responsibility(jwt(),organization,command())).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        verifyNoInteractions(service);
    }
    @Test void anotherJwtObjectCannotReplaceTheVerifiedPrincipalEvenWithEqualClaimsAndTokenText() {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(),List.of()));
        assertThatThrownBy(()->controller.responsibility(jwt(),organization,command())).isInstanceOf(AccessDeniedException.class);
        verifyNoInteractions(service);
    }
    @Test void verifiedPrincipalDelegatesToFreshScopedServiceAndReturnsNoStore() {
        Jwt jwt=jwt();SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt,List.of()));
        ProfessionalPolicyService.Responsibility request=command();
        when(service.responsibility(sid,account,organization,request)).thenReturn(2L);
        assertThat(controller.responsibility(jwt,organization,request).getHeaders().getCacheControl()).isEqualTo("no-store");
        verify(service).responsibility(sid,account,organization,request);
    }
    private ProfessionalPolicyService.Responsibility command() { return new ProfessionalPolicyService.Responsibility(account,UUID.randomUUID(),null,UUID.randomUUID(),true,null,1); }
    private Jwt jwt() { return Jwt.withTokenValue("synthetic-token").header("alg","RS256").subject(account.toString()).claim("sid",sid.toString()).expiresAt(Instant.now().plusSeconds(300)).build(); }
}
