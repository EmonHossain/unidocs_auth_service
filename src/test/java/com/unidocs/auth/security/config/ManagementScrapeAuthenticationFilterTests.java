package com.unidocs.auth.security.config;

import java.util.List;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ManagementScrapeAuthenticationFilterTests {
    private static final String TOKEN = "abcdefghijklmnopqrstuvwxyz012345_-";
    private final ManagementScrapeAuthenticationFilter filter = new ManagementScrapeAuthenticationFilter(
            new ManagementScrapeProperties(true, TOKEN));

    @AfterEach void cleanup() {
        SecurityContextHolder.clearContext();
    }

    @Test void validTokenUsesDedicatedPrincipalAndRestoresPreviousContext() throws Exception {
        SecurityContext previousContext = SecurityContextHolder.getContext();
        Authentication previousAuthentication = UsernamePasswordAuthenticationToken.authenticated(
                "previous", null, List.of(new SimpleGrantedAuthority("ROLE_OTHER")));
        previousContext.setAuthentication(previousAuthentication);
        MockHttpServletRequest request = request("Bearer " + TOKEN);
        filter.doFilter(request, new MockHttpServletResponse(), (incoming, response) -> {
            assertThat(SecurityContextHolder.getContext()).isNotSameAs(previousContext);
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertThat(authentication.isAuthenticated()).isTrue();
            assertThat(authentication.getName()).isEqualTo("prometheus-scraper");
            assertThat(authentication.getCredentials()).isNull();
            assertThat(authentication.getAuthorities()).extracting("authority").containsExactly("ROLE_METRICS_SCRAPER");
            assertThat(authentication.toString()).doesNotContain(TOKEN);
        });
        assertThat(SecurityContextHolder.getContext()).isSameAs(previousContext);
        assertThat(previousContext.getAuthentication()).isSameAs(previousAuthentication);
    }

    @Test void restoresContextWhenDownstreamFails() {
        SecurityContext previousContext = SecurityContextHolder.getContext();
        assertThatThrownBy(() -> filter.doFilter(request("Bearer " + TOKEN), new MockHttpServletResponse(),
                (incoming, response) -> { throw new ServletException("downstream"); }))
                .isInstanceOf(ServletException.class);
        assertThat(SecurityContextHolder.getContext()).isSameAs(previousContext);
        assertThat(previousContext.getAuthentication()).isNull();
    }

    @Test void invalidHeadersNeverAuthenticate() throws Exception {
        for (String header : List.of("", "Bearer ", "Bearer wrong", "bearer " + TOKEN,
                "Basic " + TOKEN, "Bearer  " + TOKEN, "Bearer " + TOKEN + " ", "Bearer " + TOKEN + ",other",
                "Bearer " + "z".repeat(TOKEN.length()), "Bearer " + "a".repeat(257),
                "Bearer " + "a".repeat(31) + "é")) {
            assertUnauthenticated(filter, request(header));
        }
        assertUnauthenticated(filter, new MockHttpServletRequest());
        MockHttpServletRequest duplicate = request("Bearer " + TOKEN);
        duplicate.addHeader("Authorization", "Bearer " + TOKEN);
        assertUnauthenticated(filter, duplicate);
        MockHttpServletRequest mixed = request("Bearer wrong");
        mixed.addHeader("Authorization", "Bearer " + TOKEN);
        assertUnauthenticated(filter, mixed);
    }

    @Test void disabledFilterDoesNotAuthenticateEvenMatchingToken() throws Exception {
        ManagementScrapeAuthenticationFilter disabled = new ManagementScrapeAuthenticationFilter(
                new ManagementScrapeProperties(false, TOKEN));
        assertUnauthenticated(disabled, request("Bearer " + TOKEN));
    }

    @Test void invalidOrMissingCredentialsCannotInheritPreexistingScrapeAuthority() throws Exception {
        SecurityContext previousContext = SecurityContextHolder.getContext();
        Authentication inherited = UsernamePasswordAuthenticationToken.authenticated(
                "inherited", null, List.of(new SimpleGrantedAuthority("ROLE_METRICS_SCRAPER")));
        previousContext.setAuthentication(inherited);
        for (MockHttpServletRequest request : List.of(new MockHttpServletRequest(), request("Bearer wrong"))) {
            filter.doFilter(request, new MockHttpServletResponse(), (incoming, response) -> {
                assertThat(SecurityContextHolder.getContext()).isNotSameAs(previousContext);
                assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            });
            assertThat(SecurityContextHolder.getContext()).isSameAs(previousContext);
            assertThat(previousContext.getAuthentication()).isSameAs(inherited);
        }
    }

    @Test void subsequentMissingHeaderCannotReuseScrapeAuthentication() throws Exception {
        filter.doFilter(request("Bearer " + TOKEN), new MockHttpServletResponse(), (incoming, response) -> {});
        assertUnauthenticated(filter, new MockHttpServletRequest());
    }

    private static MockHttpServletRequest request(String header) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", header);
        return request;
    }

    private static void assertUnauthenticated(ManagementScrapeAuthenticationFilter target,
                                            MockHttpServletRequest request) throws Exception {
        target.doFilter(request, new MockHttpServletResponse(), (incoming, response) ->
                assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull());
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}
