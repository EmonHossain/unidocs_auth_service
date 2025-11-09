package com.unidocs.auth.account.lifecycle;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import io.micrometer.core.instrument.MeterRegistry;

@Component
@ConditionalOnProperty(prefix="auth.account-lifecycle",name="maintenance-enabled",havingValue="true",matchIfMissing=true)
public class AccountLifecycleMaintenance {
    private final AccountLifecycleService service;
    private final MeterRegistry metrics;
    public AccountLifecycleMaintenance(AccountLifecycleService service,MeterRegistry metrics) { this.service=service;this.metrics=metrics; }
    @Scheduled(fixedDelayString="${auth.account-lifecycle.maintenance-delay:60000}",initialDelayString="${auth.account-lifecycle.maintenance-delay:60000}")
    public void run() {
        try { service.maintain(); } catch(RuntimeException failure) { metrics.counter("account.lifecycle.maintenance","outcome","failed").increment(); }
    }
}
