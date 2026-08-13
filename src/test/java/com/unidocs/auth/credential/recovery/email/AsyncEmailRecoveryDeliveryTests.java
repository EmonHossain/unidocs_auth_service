package com.unidocs.auth.credential.recovery.email;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.task.TaskExecutor;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.*;
@ExtendWith(MockitoExtension.class)
class AsyncEmailRecoveryDeliveryTests {
    @Mock EmailRecoveryDelivery smtp;
    @Mock TaskExecutor executor;
    @Test void enqueuesOutsideRequestAndReportsSmtpFailureWithoutExposingException() {
        Instant now=Instant.parse("2026-10-08T12:00:00Z");UUID reference=UUID.randomUUID();
        SimpleMeterRegistry metrics=new SimpleMeterRegistry();
        AsyncEmailRecoveryDelivery delivery=new AsyncEmailRecoveryDelivery(smtp,executor,Clock.fixed(now,ZoneOffset.UTC),metrics);
        delivery.deliver("user@example.com",reference,"123456",now.plusSeconds(300));
        ArgumentCaptor<Runnable> capture=ArgumentCaptor.forClass(Runnable.class);verify(executor).execute(capture.capture());verifyNoInteractions(smtp);
        doThrow(new IllegalStateException("smtp-secret")).when(smtp).deliver("user@example.com",reference,"123456",now.plusSeconds(300));
        assertThatCode(()->capture.getValue().run()).doesNotThrowAnyException();
        assertThat(metrics.get("auth.password_recovery.delivery").tag("outcome","failed").counter().count()).isEqualTo(1);
    }
    @Test void queuedExpiredCodesAreDiscardedBeforeMailboxDelivery() {
        Instant now=Instant.parse("2026-10-08T12:00:00Z");SimpleMeterRegistry metrics=new SimpleMeterRegistry();
        new AsyncEmailRecoveryDelivery(smtp,executor,Clock.fixed(now,ZoneOffset.UTC),metrics)
                .deliver("user@example.com",UUID.randomUUID(),"123456",now);
        ArgumentCaptor<Runnable> capture=ArgumentCaptor.forClass(Runnable.class);verify(executor).execute(capture.capture());capture.getValue().run();
        verifyNoInteractions(smtp);
        assertThat(metrics.get("auth.password_recovery.delivery").tag("outcome","expired").counter().count()).isEqualTo(1);
    }
}
