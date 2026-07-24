package com.unidocs.auth.authentication.api;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.authentication.browser.BrowserRefreshTransport;
import com.unidocs.auth.security.jwt.JwtKeyRing;
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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class AuthenticationMethodSecurityTests {
    private final UUID accountId = UUID.randomUUID();
    private final UUID sessionId = UUID.randomUUID();
    private final AuthenticationService service = mock(AuthenticationService.class);
    private AnnotationConfigApplicationContext context;
    private AuthenticationController controller;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        context = new AnnotationConfigApplicationContext();
        context.register(MethodSecurity.class);
        context.registerBean(com.unidocs.auth.security.config.VerifiedPrincipal.class);
        context.registerBean(AuthenticationService.class, () -> service);
        context.registerBean(JwtKeyRing.class, () -> mock(JwtKeyRing.class));
        context.registerBean(BrowserRefreshTransport.class, () -> mock(BrowserRefreshTransport.class));
        context.registerBean(AuthenticationController.class);
        context.refresh();
        controller = context.getBean(AuthenticationController.class);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        context.close();
    }

    @Test
    void everyProtectedMethodRejectsCallsOutsideHttpWithoutAuthentication() {
        Jwt supplied = jwt(accountId);
        assertThatThrownBy(() -> controller.me(supplied))
                .isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        assertThatThrownBy(() -> controller.accounts(supplied, null, 50))
                .isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        assertThatThrownBy(() -> controller.logout(supplied, new MockHttpServletRequest(), new MockHttpServletResponse()))
                .isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        assertThatThrownBy(() -> controller.logoutAll(supplied, new MockHttpServletRequest(), new MockHttpServletResponse()))
                .isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        verifyNoInteractions(service);
    }

    @Test
    void authenticatedCallerCannotSubstituteAnotherPrincipal() {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(accountId), List.of()));
        Jwt other = jwt(UUID.randomUUID());
        assertThatThrownBy(() -> controller.me(other)).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> controller.accounts(other, null, 50)).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> controller.logout(other, new MockHttpServletRequest(), new MockHttpServletResponse()))
                .isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> controller.logoutAll(other, new MockHttpServletRequest(), new MockHttpServletResponse()))
                .isInstanceOf(AccessDeniedException.class);
        verifyNoInteractions(service);
    }

    @Test
    void tokenValueEqualityCannotSubstituteForgedClaims() {
        Jwt actual = jwt(accountId);
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(actual, List.of()));
        Jwt forged = Jwt.withTokenValue(actual.getTokenValue()).header("alg", "RS256")
                .subject(UUID.randomUUID().toString()).claim("sid", UUID.randomUUID().toString())
                .issuedAt(actual.getIssuedAt()).expiresAt(actual.getExpiresAt()).build();
        assertThat(actual).isEqualTo(forged); // Spring token-value equality is not proof of verified claims.
        assertThatThrownBy(() -> controller.me(forged)).isInstanceOf(AccessDeniedException.class);
        verifyNoInteractions(service);
    }

    @Test
    void verifiedPrincipalDelegatesToExistingServerAuthoritativeChecks() {
        Jwt supplied = jwt(accountId);
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(supplied, List.of()));
        AuthenticationService.Me me = new AuthenticationService.Me(UUID.randomUUID(), "Name", sessionId, accountId, accountId);
        when(service.me(sessionId, accountId)).thenReturn(me);
        when(service.accounts(sessionId, accountId, null, 50))
                .thenReturn(new AuthenticationService.AccountPage(List.of(), null));
        assertThat(controller.me(supplied).getBody()).isEqualTo(me);
        assertThat(controller.accounts(supplied, null, 50).getBody().accounts()).isEmpty();
        controller.logout(supplied, new MockHttpServletRequest(), new MockHttpServletResponse());
        controller.logoutAll(supplied, new MockHttpServletRequest(), new MockHttpServletResponse());
        verify(service).logout(sessionId, accountId);
        verify(service).logoutAll(sessionId, accountId);
    }

    private Jwt jwt(UUID subject) {
        return Jwt.withTokenValue(subject.toString()).header("alg", "RS256")
                .subject(subject.toString()).claim("sid", sessionId.toString())
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
    }

    @Configuration(proxyBeanMethods = false)
    @EnableMethodSecurity
    static class MethodSecurity { }
}

