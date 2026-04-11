package com.unidocs.auth.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

@ConfigurationProperties("auth.management.scrape")
public record ManagementScrapeProperties(
        @DefaultValue("false") boolean enabled,
        @DefaultValue("") String token,
        @DefaultValue("false") boolean allowPrivateNetwork) {
    @ConstructorBinding
    public ManagementScrapeProperties { }

    public ManagementScrapeProperties(boolean enabled, String token) {
        this(enabled, token, false);
    }
    public void validate() {
        if (enabled && !validToken(token)) {
            throw new IllegalArgumentException("Enabled management scraping requires a valid token.");
        }
    }

    static boolean validToken(String token) {
        return token != null && token.length() >= 32 && token.length() <= 256
                && token.matches("[A-Za-z0-9_-]+");
    }

    @Override
    public String toString() {
        return "ManagementScrapeProperties[enabled=" + enabled + ", token=[REDACTED], allowPrivateNetwork="
                + allowPrivateNetwork + "]";
    }
}
