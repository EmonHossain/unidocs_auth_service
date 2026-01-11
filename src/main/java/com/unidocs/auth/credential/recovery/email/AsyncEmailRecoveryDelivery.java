package com.unidocs.auth.credential.recovery.email;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import org.springframework.core.task.TaskExecutor;
import io.micrometer.core.instrument.MeterRegistry;

/** Bounded in-memory delivery avoids a mailbox-existence SMTP timing oracle. Codes are never persisted in this queue. */
public class AsyncEmailRecoveryDelivery implements EmailRecoveryDelivery {
    private final EmailRecoveryDelivery smtp;
    private final TaskExecutor executor;
    private final Clock clock;
    private final MeterRegistry metrics;
    public AsyncEmailRecoveryDelivery(EmailRecoveryDelivery smtp,TaskExecutor executor,Clock clock,MeterRegistry metrics) {
        this.smtp=smtp;this.executor=executor;this.clock=clock;this.metrics=metrics;
    }
    @Override public void deliver(String email,UUID id,String code,Instant expiresAt) {
        executor.execute(()->{
            if(!clock.instant().isBefore(expiresAt)) { count("expired");return; }
            try { smtp.deliver(email,id,code,expiresAt);count("succeeded"); }
            catch(RuntimeException failure) { count("failed"); }
        });
    }
    private void count(String outcome) { metrics.counter("auth.password_recovery.delivery","outcome",outcome).increment(); }
}
