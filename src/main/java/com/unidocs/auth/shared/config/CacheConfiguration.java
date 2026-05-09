package com.unidocs.auth.shared.config;

import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Configuration;

/** Enables the bounded, disposable Caffeine cache configured in application.properties. */
@Configuration(proxyBeanMethods = false)
@EnableCaching
public class CacheConfiguration {
}
