package com.unidocs.auth.security.spicedb;

import java.net.URI;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

// The legacy prefix is retained so existing deployment configuration and credentials keep working.
@ConfigurationProperties("auth.spicedb.projection")
public record SpiceDbOrganizationSyncProperties(@DefaultValue("false") boolean enabled,
        @DefaultValue("spicedb-api-gateway:50051") String endpoint, @DefaultValue("") String presharedKey,
        @DefaultValue("true") boolean plaintext, @DefaultValue("500") long deadlineMillis,
        @DefaultValue("1000") int maxBatchSize, @DefaultValue("10") int claimLimit,
        @DefaultValue("300") long leaseSeconds, @DefaultValue("5000") long pollMillis) {
    public SpiceDbOrganizationSyncProperties {
        if (deadlineMillis < 1 || deadlineMillis > 10_000 || maxBatchSize < 1 || maxBatchSize > 1_000
                || claimLimit < 1 || claimLimit > 100 || leaseSeconds < 10 || leaseSeconds > 3_600
                || pollMillis < 100 || pollMillis > 60_000) {
            throw new IllegalArgumentException("SpiceDB organization sync limits are outside their supported bounds.");
        }
        if (endpoint == null || endpoint.isBlank() || presharedKey == null
                || enabled && (presharedKey.isBlank() || !validEndpoint(endpoint))) {
            throw new IllegalArgumentException("Enabled SpiceDB organization sync requires a gateway endpoint and distinct relationship-writer credential.");
        }
    }

    private static boolean validEndpoint(String value) {
        try {
            URI uri = URI.create("https://" + value);
            return uri.getHost() != null && uri.getPort() >= -1 && uri.getUserInfo() == null
                    && uri.getQuery() == null && uri.getFragment() == null && !value.contains("/");
        } catch (RuntimeException invalid) {
            return false;
        }
    }
}
