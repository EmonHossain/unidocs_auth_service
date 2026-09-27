package com.unidocs.auth.security.config;

import java.util.List;
import java.util.UUID;
import jakarta.servlet.ServletException;
import com.unidocs.auth.shared.config.TrustedRequestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthenticatedDiagnosticContextFilterTests {
    private final AuthenticatedDiagnosticContextFilter filter = new AuthenticatedDiagnosticContextFilter();
    @AfterEach void cleanup() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
        MDC.clear();
    }

    @Test void authenticatedSubjectIsTheOnlyIdentityAndOrganizationRequiresExplicitAuthorization() throws Exception {
        UUID principal = UUID.randomUUID();
        UUID organization = UUID.randomUUID();
        authenticate(principal.toString());
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-User-Id", UUID.randomUUID().toString());
        request.addHeader("X-Tenant-Id", UUID.randomUUID().toString());
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        filter.doFilter(request, new MockHttpServletResponse(), (incoming, response) -> {
            assertThat(MDC.get(TrustedRequestContext.USER_ID)).isEqualTo(principal.toString());
            assertThat(MDC.get(TrustedRequestContext.TENANT_ID)).isNull();
            TrustedRequestContext.authorizedOrganization(organization);
            assertThat(MDC.get(TrustedRequestContext.TENANT_ID)).isEqualTo(organization.toString());
        });
        assertThat(TrustedRequestContext.principal(request)).isEqualTo(principal);
        assertThat(TrustedRequestContext.organization(request)).isEqualTo(organization);
        assertThat(MDC.get(TrustedRequestContext.USER_ID)).isNull();
        assertThat(MDC.get(TrustedRequestContext.TENANT_ID)).isNull();
    }

    @Test void anonymousAuthenticationCannotMarkOrganizationAndPriorMdcIsHiddenDuringRequest() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("anonymous", "anonymous",
                List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))));
        MDC.put(TrustedRequestContext.USER_ID, "previous-user");
        MDC.put(TrustedRequestContext.TENANT_ID, "previous-tenant");
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        filter.doFilter(request, new MockHttpServletResponse(), (incoming, response) -> {
            TrustedRequestContext.authorizedOrganization(UUID.randomUUID());
            assertThat(MDC.get(TrustedRequestContext.USER_ID)).isNull();
            assertThat(MDC.get(TrustedRequestContext.TENANT_ID)).isNull();
        });
        assertThat(TrustedRequestContext.principal(request)).isNull();
        assertThat(TrustedRequestContext.organization(request)).isNull();
        assertThat(MDC.get(TrustedRequestContext.USER_ID)).isEqualTo("previous-user");
        assertThat(MDC.get(TrustedRequestContext.TENANT_ID)).isEqualTo("previous-tenant");
    }

    @Test void malformedSubjectCannotPopulateDiagnostics() throws Exception {
        for (String subject : List.of("1-1-1-1-1", "invalid", UUID.randomUUID().toString().toUpperCase(java.util.Locale.ROOT))) {
            authenticate(subject);
            MockHttpServletRequest request = new MockHttpServletRequest();
            filter.doFilter(request, new MockHttpServletResponse(), (incoming, response) ->
                    assertThat(MDC.get(TrustedRequestContext.USER_ID)).isNull());
            assertThat(TrustedRequestContext.principal(request)).isNull();
        }
    }

    @Test void downstreamFailureRestoresPriorMdc() {
        authenticate(UUID.randomUUID().toString());
        MDC.put(TrustedRequestContext.USER_ID, "previous-user");
        MDC.put(TrustedRequestContext.TENANT_ID, "previous-tenant");
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        assertThatThrownBy(() -> filter.doFilter(request, new MockHttpServletResponse(), (incoming, response) -> {
            TrustedRequestContext.authorizedOrganization(UUID.randomUUID());
            throw new ServletException("failure");
        })).isInstanceOf(ServletException.class);
        assertThat(MDC.get(TrustedRequestContext.USER_ID)).isEqualTo("previous-user");
        assertThat(MDC.get(TrustedRequestContext.TENANT_ID)).isEqualTo("previous-tenant");
    }

    private void authenticate(String subject) {
        Jwt jwt = Jwt.withTokenValue("test-token").header("alg", "RS256").subject(subject)
                .claim("user.id", "forged-user").claim("tenant.id", "forged-tenant")
                .claim("labels.tenant_id", "forged-tenant").build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of()));
    }
}
