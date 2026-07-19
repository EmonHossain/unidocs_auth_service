package com.unidocs.auth.account.lifecycle;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.mockito.ArgumentCaptor;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class AccountLifecycleUnitTests {
    @Test void retentionUsesUtcCalendarMonthsAndRejectsOtherPolicies() {
        Instant now=Instant.parse("2026-01-31T12:00:00Z");
        assertThat(new RetentionPolicy(3).deadline(now)).isEqualTo(Instant.parse("2026-04-30T12:00:00Z"));
        assertThat(new RetentionPolicy(12).deadline(Instant.parse("2024-02-29T12:00:00Z"))).isEqualTo(Instant.parse("2025-02-28T12:00:00Z"));
        assertThatThrownBy(()->new RetentionPolicy(6)).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void recoveryRejectsDeadlineEqualityAndNonRemovedStates() {
        RetentionPolicy policy=new RetentionPolicy(3);Instant deadline=Instant.parse("2026-10-02T00:00:00Z");
        assertThat(policy.recoverable("SOFT_DELETED",deadline,deadline.minusNanos(1))).isTrue();
        assertThat(policy.recoverable("SOFT_DELETED",deadline,deadline)).isFalse();
        assertThat(policy.recoverable("PURGED",deadline,deadline.minusSeconds(1))).isFalse();
    }
    @Test void smtpNoticeNamesAccountReasonAndDeadlineUsingMockito() {
        @SuppressWarnings("unchecked") ObjectProvider<JavaMailSender> provider=mock(ObjectProvider.class);
        JavaMailSender sender=mock(JavaMailSender.class);when(provider.getIfAvailable()).thenReturn(sender);when(provider.getObject()).thenReturn(sender);
        SmtpAccountNoticeDelivery delivery=new SmtpAccountNoticeDelivery(provider,true,"security@example.com");
        LifecycleRepository.Notice notice=new LifecycleRepository.Notice(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),
                "ORGANIZATION_MEMBER_BLACKLISTED","Policy violation",Instant.parse("2026-10-03T00:00:00Z"),Instant.parse("2026-10-02T00:00:00Z"));
        delivery.deliver("member@example.com",notice);
        ArgumentCaptor<SimpleMailMessage> message=ArgumentCaptor.forClass(SimpleMailMessage.class);verify(sender).send(message.capture());
        assertThat(message.getValue().getText()).contains(notice.accountId().toString(),notice.organizationId().toString(),"Policy violation",notice.deadline().toString());
        assertThat(message.getValue().getTo()).containsExactly("member@example.com");
    }
    @Test void disabledDeliveryFailsBeforeSendingAndRequestsHidePasswords() {
        @SuppressWarnings("unchecked") ObjectProvider<JavaMailSender> provider=mock(ObjectProvider.class);
        SmtpAccountNoticeDelivery delivery=new SmtpAccountNoticeDelivery(provider,false,"security@example.com");
        assertThat(delivery.enabled()).isFalse();assertThatThrownBy(()->delivery.deliver("x",null)).isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(provider);
        assertThat(new LifecycleRequests.Remove(null,UUID.randomUUID(),"secret").toString()).doesNotContain("secret");
        assertThat(new LifecycleRequests.Restore("secret").toString()).doesNotContain("secret");
    }
    @Test void retentionScheduleRunsWithoutKafkaPublisherConfiguration() {
        AccountLifecycleService service=mock(AccountLifecycleService.class);
        io.micrometer.core.instrument.simple.SimpleMeterRegistry metrics=new io.micrometer.core.instrument.simple.SimpleMeterRegistry();
        try(org.springframework.context.annotation.AnnotationConfigApplicationContext context=new org.springframework.context.annotation.AnnotationConfigApplicationContext()) {
            context.register(AccountLifecycleConfiguration.class,AccountLifecycleMaintenance.class);
            context.registerBean(AccountLifecycleService.class,()->service);
            context.registerBean(io.micrometer.core.instrument.MeterRegistry.class,()->metrics);
            context.refresh();
            org.springframework.scheduling.annotation.ScheduledAnnotationBeanPostProcessor scheduler=context.getBean(org.springframework.scheduling.annotation.ScheduledAnnotationBeanPostProcessor.class);
            assertThat(scheduler.getScheduledTasks()).hasSize(1);
            scheduler.getScheduledTasks().iterator().next().getTask().getRunnable().run();
            verify(service).maintain();
        }
    }
}
