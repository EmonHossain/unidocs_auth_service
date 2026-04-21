package com.unidocs.auth.security.ratelimit;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;
@Component
public class RateLimitKeyResolver {
    public String resolve(RateLimitProperties properties, RateLimitPolicy policy, HttpServletRequest request) {
        String peer = request.getRemoteAddr();
        if (peer == null || peer.isBlank()) peer = "internal";
        try {
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(peer.getBytes(StandardCharsets.UTF_8)));
            return properties.keyPrefix() + ":" + policy.name() + ":" + digest;
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is unavailable.");
        }
    }
}
