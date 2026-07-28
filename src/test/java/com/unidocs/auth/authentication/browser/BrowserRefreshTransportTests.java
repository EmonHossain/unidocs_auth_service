package com.unidocs.auth.authentication.browser;

import com.unidocs.auth.authentication.api.RefreshRequest;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.session.domain.RefreshSecret;
import jakarta.servlet.http.Cookie;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import tools.jackson.databind.json.JsonMapper;
import static org.assertj.core.api.Assertions.*;

class BrowserRefreshTransportTests {
    private static final String ORIGIN = "https://drive.example";
    private static final String SECRET = RefreshSecret.create().value();
    private final BrowserRefreshTransport transport = new BrowserRefreshTransport(
            new BrowserRefreshProperties(List.of(ORIGIN)));

    @Test
    void apiModeRequiresNoTransportHeaderAndIgnoresAmbientCookies() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie(BrowserRefreshTransport.COOKIE, "invalid"));
        request.addHeader(HttpHeaders.ORIGIN, "https://evil.example");
        assertThat(transport.validate(request)).isFalse();
        RefreshRequest body = new RefreshRequest(SECRET);
        assertThat(transport.refreshRequest(false, body, request)).isEqualTo(body);
        assertThatThrownBy(() -> transport.refreshRequest(false, null, request))
                .isInstanceOf(AuthenticationFailure.class);
    }

    @Test
    void exactTrustedOriginEnablesBrowserMode() {
        assertThat(transport.validate(browserRequest())).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"null", "https://evil.example", "http://drive.example", "https://drive.example.evil",
            "https://drive.example/", "https://drive.example:443", "https://drive.example https://evil.example"})
    void browserModeRejectsMissingOrSpoofedOrigin(String origin) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE);
        if (origin != null) request.addHeader(HttpHeaders.ORIGIN, origin);
        assertThatThrownBy(() -> transport.validate(request)).isInstanceOf(BrowserRefreshDenied.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "Cookie", "COOKIE", "cookie, cookie", "header", " cookie "})
    void rejectsUnknownOrAmbiguousTransport(String mode) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(BrowserRefreshTransport.HEADER, mode);
        request.addHeader(HttpHeaders.ORIGIN, ORIGIN);
        assertThatThrownBy(() -> transport.validate(request)).isInstanceOf(BrowserRefreshDenied.class);
    }

    @Test
    void duplicateTransportOrOriginHeadersAreDenied() {
        MockHttpServletRequest request = browserRequest();
        request.addHeader(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE);
        assertThatThrownBy(() -> transport.validate(request)).isInstanceOf(BrowserRefreshDenied.class);
        MockHttpServletRequest duplicateOrigin = browserRequest();
        duplicateOrigin.addHeader(HttpHeaders.ORIGIN, ORIGIN);
        assertThatThrownBy(() -> transport.validate(duplicateOrigin)).isInstanceOf(BrowserRefreshDenied.class);
    }

    @Test
    void emptyAllowlistDisablesBrowserMode() {
        BrowserRefreshTransport disabled = new BrowserRefreshTransport(new BrowserRefreshProperties(null));
        assertThatThrownBy(() -> disabled.validate(browserRequest())).isInstanceOf(BrowserRefreshDenied.class);
    }

    @Test
    void readsExactlyOneRefreshCookieAndIgnoresUnrelatedCookies() {
        MockHttpServletRequest request = browserRequest();
        request.setCookies(new Cookie("unrelated", "value"), new Cookie(BrowserRefreshTransport.COOKIE, SECRET));
        assertThat(transport.refreshRequest(true, null, request).refreshToken()).isEqualTo(SECRET);
    }

    @Test
    void browserModeRejectsBodyCredentialsAndDuplicateCookies() {
        MockHttpServletRequest request = browserRequest();
        request.setCookies(new Cookie(BrowserRefreshTransport.COOKIE, SECRET));
        assertThatThrownBy(() -> transport.refreshRequest(true, new RefreshRequest(SECRET), request))
                .isInstanceOf(AuthenticationFailure.class);
        request.setCookies(new Cookie(BrowserRefreshTransport.COOKIE, SECRET), new Cookie(BrowserRefreshTransport.COOKIE, SECRET));
        assertThatThrownBy(() -> transport.refreshRequest(true, null, request)).isInstanceOf(AuthenticationFailure.class);
    }

    @Test
    void browserModeRejectsDuplicateCookiesEvenWhenFirstValueIsNull() {
        MockHttpServletRequest request = browserRequest();
        request.setCookies(new Cookie(BrowserRefreshTransport.COOKIE, null), new Cookie(BrowserRefreshTransport.COOKIE, SECRET));
        assertThatThrownBy(() -> transport.refreshRequest(true, null, request)).isInstanceOf(AuthenticationFailure.class);
    }

    @Test
    void browserModeRejectsMissingCookie() {
        assertThatThrownBy(() -> transport.refreshRequest(true, null, browserRequest()))
                .isInstanceOf(AuthenticationFailure.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "secret", "00000000-0000-0000-0000-000000000000.short"})
    void browserModeRejectsMalformedCookiesWithoutLeakingThem(String value) {
        MockHttpServletRequest request = browserRequest();
        request.setCookies(new Cookie(BrowserRefreshTransport.COOKIE, value));
        assertThatThrownBy(() -> transport.refreshRequest(true, null, request))
                .isInstanceOf(AuthenticationFailure.class).hasMessage("Authentication failed.");
    }

    @Test
    void browserModeRejectsOverlongCookies() {
        MockHttpServletRequest request = browserRequest();
        request.setCookies(new Cookie(BrowserRefreshTransport.COOKIE, "s".repeat(129)));
        assertThatThrownBy(() -> transport.refreshRequest(true, null, request)).isInstanceOf(AuthenticationFailure.class);
    }

    @Test
    void browserResponseStoresSecretOnlyInSecureHostCookie() {
        TokenResponse tokens = tokens();
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        ResponseEntity<TokenResponse> response = transport.response(true, tokens, servletResponse);
        String cookie = servletResponse.getHeader(HttpHeaders.SET_COOKIE);
        assertThat(cookie).startsWith(BrowserRefreshTransport.COOKIE + "=" + SECRET + ";")
                .contains("Path=/", "Secure", "HttpOnly", "SameSite=Strict")
                .doesNotContain("Domain=", "Max-Age=", "Expires=");
        assertThat(response.getHeaders().getCacheControl()).contains("no-store");
        assertThat(response.getBody()).isEqualTo(new TokenResponse(tokens.tokenType(), tokens.accessToken(),
                tokens.expiresIn(), null, tokens.sessionId(), tokens.loginAccountId()));
        String json = JsonMapper.builder().build().writeValueAsString(response.getBody());
        assertThat(json).doesNotContain(SECRET).contains("access-token");
    }

    @Test
    void apiResponsePreservesBodyAndDoesNotSetCookie() {
        TokenResponse tokens = tokens();
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        ResponseEntity<TokenResponse> response = transport.response(false, tokens, servletResponse);
        assertThat(response.getBody()).isEqualTo(tokens);
        assertThat(response.getHeaders().getCacheControl()).contains("no-store");
        assertThat(servletResponse.getHeaders(HttpHeaders.SET_COOKIE)).isEmpty();
    }

    @Test
    void clearExpiresBrowserCookieWithSameSecurityFlags() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        transport.clear(true, response);
        assertThat(response.getHeader(HttpHeaders.SET_COOKIE)).startsWith(BrowserRefreshTransport.COOKIE + "=;")
                .contains("Max-Age=0", "Path=/", "Secure", "HttpOnly", "SameSite=Strict").doesNotContain("Domain=");
        MockHttpServletResponse apiResponse = new MockHttpServletResponse();
        transport.clear(false, apiResponse);
        assertThat(apiResponse.getHeaders(HttpHeaders.SET_COOKIE)).isEmpty();
    }

    @Test
    void denialExceptionDoesNotExposeOrigin() {
        MockHttpServletRequest request = browserRequest();
        request.removeHeader(HttpHeaders.ORIGIN);
        request.addHeader(HttpHeaders.ORIGIN, "https://secret-attacker.example");
        assertThatThrownBy(() -> transport.validate(request)).isInstanceOf(BrowserRefreshDenied.class)
                .hasMessageNotContaining("secret-attacker");
    }

    private static MockHttpServletRequest browserRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE);
        request.addHeader(HttpHeaders.ORIGIN, ORIGIN);
        return request;
    }

    private static TokenResponse tokens() {
        return new TokenResponse("Bearer", "access-token", 300, SECRET, UUID.randomUUID(), UUID.randomUUID());
    }
}


