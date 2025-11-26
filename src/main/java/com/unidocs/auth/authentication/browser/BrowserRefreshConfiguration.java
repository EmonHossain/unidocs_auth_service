package com.unidocs.auth.authentication.browser;

import java.util.List;
import com.unidocs.auth.shared.config.ApiVersionProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({BrowserRefreshProperties.class, ApiVersionProperties.class})
public class BrowserRefreshConfiguration {
    @Bean
    CorsConfigurationSource corsConfigurationSource(BrowserRefreshProperties properties, ApiVersionProperties api) {
        CorsConfiguration cors = new CorsConfiguration();
        cors.setAllowedOrigins(properties.allowedOrigins());
        cors.setAllowedMethods(List.of("POST"));
        cors.setAllowedHeaders(List.of("Content-Type", "Authorization", BrowserRefreshTransport.HEADER));
        cors.setAllowCredentials(true);
        cors.setMaxAge(300L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(api.path("/auth/**"), cors);
        return source;
    }
}

