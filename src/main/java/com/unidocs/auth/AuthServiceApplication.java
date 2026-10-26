package com.unidocs.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurationExcludeFilter;
import org.springframework.boot.context.TypeExcludeFilter;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;
import com.unidocs.auth.offline.OfflineConfiguration;

@SpringBootConfiguration
@EnableAutoConfiguration
@Import({AuthServiceApplication.OnlineConfiguration.class, OfflineConfiguration.class})
public class AuthServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }

    @Configuration(proxyBeanMethods = false)
    @Profile("!offline")
    @ComponentScan(basePackages = "com.unidocs.auth", excludeFilters = {
            @ComponentScan.Filter(type = FilterType.CUSTOM, classes = TypeExcludeFilter.class),
            @ComponentScan.Filter(type = FilterType.CUSTOM, classes = AutoConfigurationExcludeFilter.class),
            @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE,
                    classes = {AuthServiceApplication.class, OnlineConfiguration.class, OfflineConfiguration.class})})
    public static class OnlineConfiguration { }
}
