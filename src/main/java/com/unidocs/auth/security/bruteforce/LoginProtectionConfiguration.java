package com.unidocs.auth.security.bruteforce;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(LoginProtectionProperties.class)
public class LoginProtectionConfiguration { }
