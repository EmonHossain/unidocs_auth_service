package com.unidocs.auth.registration.application;

import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class VerificationTokens {
    private final SecureRandom random = new SecureRandom();
    private final BCryptPasswordEncoder codes = new BCryptPasswordEncoder();
    public String generate() {
        return String.format(java.util.Locale.ROOT, "%06d", random.nextInt(1_000_000));
    }
    public String hash(String token) { return codes.encode(token); }
    public boolean matches(String token, String expectedHash) {
        if (token == null || expectedHash == null) return false;
        if (expectedHash.startsWith("$2")) return codes.matches(token, expectedHash);
        // Existing high-entropy challenges remain usable until their original expiry.
        try {
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
            return MessageDigest.isEqual(digest.getBytes(StandardCharsets.US_ASCII), expectedHash.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException failure) { throw new IllegalStateException("Required digest unavailable."); }
    }
}
