package com.unidocs.auth.security.spicedb;

import java.net.URI;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("auth.spicedb")
public record SpiceDbProperties(@DefaultValue("false") boolean enabled,
        @DefaultValue("spicedb:50051") String endpoint, @DefaultValue("") String presharedKey,
        @DefaultValue("false") boolean plaintext, @DefaultValue("500") long deadlineMillis) {
    public SpiceDbProperties {
        if (deadlineMillis < 1 || deadlineMillis > 10_000) {
            throw new IllegalArgumentException("SpiceDB RPC deadline must be between 1 and 10000 milliseconds.");
        }
        if (enabled && (!validEndpoint(endpoint) || presharedKey == null || presharedKey.isBlank())) {
            throw new IllegalArgumentException("Enabled SpiceDB integration requires an endpoint and preshared key.");
        }
    }

    private static boolean validEndpoint(String value) {
        try {
            URI uri = URI.create("https://" + value);
            return value != null && !value.isBlank() && uri.getHost() != null && uri.getPort() >= -1
                    && uri.getUserInfo() == null && uri.getQuery() == null && uri.getFragment() == null
                    && !value.contains("/");
        } catch (RuntimeException exception) {
            return false;
        }
    }
}
