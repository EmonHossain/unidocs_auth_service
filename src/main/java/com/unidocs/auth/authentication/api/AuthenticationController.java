package com.unidocs.auth.authentication.api;

import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.security.jwt.JwtKeyRing;

@io.swagger.v3.oas.annotations.tags.Tag(name = "Authentication", description = "Login, token rotation, session revocation and current account context.")
@RestController
public class AuthenticationController {
    private final AuthenticationService authentication;
    private final JwtKeyRing keys;
    private final com.unidocs.auth.authentication.browser.BrowserRefreshTransport browserRefresh;
    public AuthenticationController(AuthenticationService authentication, JwtKeyRing keys, com.unidocs.auth.authentication.browser.BrowserRefreshTransport browserRefresh) {
        this.authentication = authentication; this.keys = keys; this.browserRefresh = browserRefresh;
    }

    @io.swagger.v3.oas.annotations.Operation(summary = "Sign in", description = "Authenticate with email and password; create a session and initial LOGIN account grant.")
    @PostMapping("${api.version.base-path}/auth/login")
    ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest servletRequest, jakarta.servlet.http.HttpServletResponse servletResponse) {
        boolean browser = browserRefresh.validate(servletRequest);
        return browserRefresh.response(browser, authentication.login(request, servletRequest.getRemoteAddr()), servletResponse);
    }

    @io.swagger.v3.oas.annotations.Operation(summary = "Rotate refresh token", description = "Exchange a single-use refresh secret for new tokens. Replay revokes the affected session. JSON mode requires a body; cookie mode requires no body.")
    @PostMapping("${api.version.base-path}/auth/refresh")
    ResponseEntity<TokenResponse> refresh(@Valid @RequestBody(required = false) RefreshRequest request,
            HttpServletRequest servletRequest, jakarta.servlet.http.HttpServletResponse servletResponse) {
        boolean browser = browserRefresh.validate(servletRequest);
        try {
            RefreshRequest supplied = browserRefresh.refreshRequest(browser, request, servletRequest);
            return browserRefresh.response(browser, authentication.refresh(supplied), servletResponse);
        } catch (com.unidocs.auth.authentication.application.AuthenticationFailure failure) {
            browserRefresh.clear(browser, servletResponse);
            throw failure;
        }
    }

    @io.swagger.v3.oas.annotations.Operation(summary = "Sign in to an account", description = "Authenticate the selected account and create its initial session grant.")
    @PostMapping("${api.version.base-path}/auth/accounts/{accountId}/login")
    ResponseEntity<TokenResponse> loginAccount(@PathVariable UUID accountId, @Valid @RequestBody AccountLoginRequest request, HttpServletRequest servletRequest, jakarta.servlet.http.HttpServletResponse servletResponse) {
        boolean browser = browserRefresh.validate(servletRequest);
        return browserRefresh.response(browser, authentication.loginAccount(accountId,request,servletRequest.getRemoteAddr()), servletResponse);
    }

    @io.swagger.v3.oas.annotations.Operation(summary = "End current session", description = "Revoke the current session and its account grants.")
    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "204", description = "Current session revoked.")
    @PostMapping("${api.version.base-path}/auth/logout")
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    ResponseEntity<Void> logout(@AuthenticationPrincipal Jwt jwt, HttpServletRequest servletRequest, jakarta.servlet.http.HttpServletResponse servletResponse) {
        boolean browser = browserRefresh.validate(servletRequest);
        authentication.logout(session(jwt), account(jwt));
        browserRefresh.clear(browser, servletResponse);
        return ResponseEntity.noContent().header("Cache-Control", "no-store").build();
    }

    @io.swagger.v3.oas.annotations.Operation(summary = "End all sessions", description = "Revoke all sessions in the current linked account group.")
    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "204", description = "All sessions in the linked account group revoked.")
    @PostMapping("${api.version.base-path}/auth/logout-all")
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    ResponseEntity<Void> logoutAll(@AuthenticationPrincipal Jwt jwt, HttpServletRequest servletRequest,
            jakarta.servlet.http.HttpServletResponse servletResponse) {
        boolean browser = browserRefresh.validate(servletRequest);
        authentication.logoutAll(session(jwt), account(jwt));
        browserRefresh.clear(browser, servletResponse);
        return ResponseEntity.noContent().header("Cache-Control", "no-store").build();
    }

    @io.swagger.v3.oas.annotations.Operation(summary = "Get current identity", description = "Return current session and account context after server-side validity checks.")
    @GetMapping("${api.version.base-path}/me")
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    ResponseEntity<AuthenticationService.Me> me(@AuthenticationPrincipal Jwt jwt) {
        return noStore(authentication.me(session(jwt), account(jwt)));
    }

    @io.swagger.v3.oas.annotations.Operation(summary = "List linked accounts", description = "Return a bounded page of linked accounts. Linking alone does not grant account access.")
    @GetMapping("${api.version.base-path}/me/accounts")
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    ResponseEntity<AuthenticationService.AccountPage> accounts(@AuthenticationPrincipal Jwt jwt,
            @RequestParam(required = false) UUID after, @RequestParam(defaultValue = "50") @Min(1) @Max(100) int limit) {
        return noStore(authentication.accounts(session(jwt), account(jwt), after, limit));
    }

    @io.swagger.v3.oas.annotations.Operation(summary = "Get public signing keys", description = "Publish public keys for local JWT signature verification. Private signing material is never exposed.")
    @GetMapping("/.well-known/jwks.json")
    ResponseEntity<java.util.Map<String, Object>> jwks() {
        return ResponseEntity.ok().header("Cache-Control", "public, max-age=60").body(keys.jwks());
    }

    private static UUID session(Jwt jwt) { return UUID.fromString(jwt.getClaimAsString("sid")); }
    private static UUID account(Jwt jwt) { return UUID.fromString(jwt.getSubject()); }
    private static <T> ResponseEntity<T> noStore(T body) {
        return ResponseEntity.ok().header("Cache-Control", "no-store").header("Pragma", "no-cache").body(body);
    }
}
