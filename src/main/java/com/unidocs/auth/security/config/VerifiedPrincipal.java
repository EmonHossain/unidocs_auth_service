package com.unidocs.auth.security.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;

/** Bind method input to the actual verified context object, not JWT token-value equality. */
public final class VerifiedPrincipal {
    public boolean matches(Authentication authentication, Jwt supplied) {
        return supplied != null && authentication != null && authentication.isAuthenticated()
                && authentication.getPrincipal() == supplied;
    }
}
