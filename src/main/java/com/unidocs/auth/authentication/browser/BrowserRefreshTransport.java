package com.unidocs.auth.authentication.browser;


import java.util.Collections;
import java.util.List;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import com.unidocs.auth.authentication.api.RefreshRequest;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.session.domain.RefreshSecret;

/** Cookies are never an access authentication mechanism; explicit browser mode is required. */
@Component
public class BrowserRefreshTransport {
    public static final String HEADER = "X-Auth-Transport";
    public static final String MODE = "cookie";
    public static final String COOKIE = "__Host-auth-refresh";
    private final BrowserRefreshProperties properties;

    public BrowserRefreshTransport(BrowserRefreshProperties properties) {
        this.properties = properties;
    }

    public boolean validate(HttpServletRequest request) {
        List<String> modes = Collections.list(request.getHeaders(HEADER));
        if (modes.isEmpty()) return false;
        List<String> origins = Collections.list(request.getHeaders(HttpHeaders.ORIGIN));
        if (modes.size() != 1 || !MODE.equals(modes.getFirst()) || origins.size() != 1
                || !properties.allowedOrigins().contains(origins.getFirst())) throw new BrowserRefreshDenied();
        return true;
    }

    public RefreshRequest refreshRequest(boolean browser, RefreshRequest body, HttpServletRequest request) {
        if (!browser) {
            if (body == null) throw new AuthenticationFailure();
            return body;
        }
        if (body != null) throw new AuthenticationFailure();
        String token = null;
        int matches = 0;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (COOKIE.equals(cookie.getName())) {
                    if (++matches > 1) throw new AuthenticationFailure();
                    token = cookie.getValue();
                }
            }
        }
        try { RefreshSecret.parse(token); }
        catch (IllegalArgumentException invalid) { throw new AuthenticationFailure(); }
        return new RefreshRequest(token);
    }

    public ResponseEntity<TokenResponse> response(boolean browser, TokenResponse token, HttpServletResponse response) {
        if (browser) {
            response.addHeader(HttpHeaders.SET_COOKIE, cookie(token.refreshToken()).build().toString());
            token = new TokenResponse(token.tokenType(), token.accessToken(), token.expiresIn(), null,
                    token.sessionId(), token.loginAccountId());
        }
        return ResponseEntity.ok().header(HttpHeaders.CACHE_CONTROL, "no-store").header(HttpHeaders.PRAGMA, "no-cache").body(token);
    }

    public void clear(boolean browser, HttpServletResponse response) {
        if (browser) response.addHeader(HttpHeaders.SET_COOKIE, cookie("").maxAge(0).build().toString());
    }

    private static ResponseCookie.ResponseCookieBuilder cookie(String value) {
        return ResponseCookie.from(COOKIE, value).httpOnly(true).secure(true).sameSite("Strict").path("/");
    }
}
