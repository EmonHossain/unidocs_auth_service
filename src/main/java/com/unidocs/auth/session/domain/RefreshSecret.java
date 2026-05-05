package com.unidocs.auth.session.domain;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

public record RefreshSecret(UUID id, String secret) {
    private static final SecureRandom RANDOM = new SecureRandom();

    public static RefreshSecret create() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return new RefreshSecret(UUID.randomUUID(), Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
    }

    public static RefreshSecret parse(String value) {
        if (value == null || !value.matches("[0-9a-fA-F-]{36}\\.[A-Za-z0-9_-]{43}")) {
            throw new IllegalArgumentException("Invalid refresh credential.");
        }
        return new RefreshSecret(UUID.fromString(value.substring(0, 36)), value.substring(37));
    }

    public String value() { return id + "." + secret; }

    public String hash() {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(secret.getBytes(StandardCharsets.US_ASCII)));
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable.");
        }
    }

    public boolean matches(String hash) {
        return MessageDigest.isEqual(hash().getBytes(StandardCharsets.US_ASCII), hash.getBytes(StandardCharsets.US_ASCII));
    }

    @Override public String toString() { return "RefreshSecret[REDACTED]"; }
}
