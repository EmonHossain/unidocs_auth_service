package com.unidocs.auth.organization.application;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import org.springframework.stereotype.Component;

@Component
public class InvitationTokens {
    private final SecureRandom random=new SecureRandom();
    public String generate() {
        byte[] bytes=new byte[32]; random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    public String hash(String token) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8))); }
        catch(NoSuchAlgorithmException unavailable) { throw new IllegalStateException("Required hash algorithm is unavailable."); }
    }
    public boolean matches(String token, String hash) {
        return MessageDigest.isEqual(hash(token).getBytes(StandardCharsets.US_ASCII),hash.getBytes(StandardCharsets.US_ASCII));
    }
}
