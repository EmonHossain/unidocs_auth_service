package com.unidocs.auth.account.lifecycle;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/** Retention and notice schedules also run when Kafka publication is disabled. */
@Configuration(proxyBeanMethods=false)
@EnableScheduling
public class AccountLifecycleConfiguration { }
