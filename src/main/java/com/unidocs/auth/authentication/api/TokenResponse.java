package com.unidocs.auth.authentication.api;

import java.util.UUID;

public record TokenResponse(@io.swagger.v3.oas.annotations.media.Schema(description = "Authorization scheme.", example = "Bearer", accessMode = io.swagger.v3.oas.annotations.media.Schema.AccessMode.READ_ONLY) String tokenType, @io.swagger.v3.oas.annotations.media.Schema(description = "Short-lived JWT for the Authorization header.", accessMode = io.swagger.v3.oas.annotations.media.Schema.AccessMode.READ_ONLY) String accessToken, @io.swagger.v3.oas.annotations.media.Schema(description = "Access-token lifetime in seconds.", accessMode = io.swagger.v3.oas.annotations.media.Schema.AccessMode.READ_ONLY) long expiresIn,
        @io.swagger.v3.oas.annotations.media.Schema(description = "Single-use refresh secret. Null when delivered using browser cookie transport.", accessMode = io.swagger.v3.oas.annotations.media.Schema.AccessMode.READ_ONLY) String refreshToken, UUID sessionId, UUID loginAccountId) {
    @Override public String toString() { return "TokenResponse[REDACTED]"; }
}
