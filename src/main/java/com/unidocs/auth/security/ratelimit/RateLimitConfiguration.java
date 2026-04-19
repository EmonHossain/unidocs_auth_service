package com.unidocs.auth.security.ratelimit;
import com.unidocs.auth.security.config.SecurityProblemWriter;
import com.unidocs.auth.shared.config.ApiVersionProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({RateLimitProperties.class, ApiVersionProperties.class})
public class RateLimitConfiguration {
    @Bean
    FilterRegistrationBean<RateLimitFilter> rateLimitFilter(RateLimitService service, SecurityProblemWriter problems, ApiVersionProperties api) {
        FilterRegistrationBean<RateLimitFilter> registration = new FilterRegistrationBean<>(new RateLimitFilter(service, problems, api));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return registration;
    }
}

