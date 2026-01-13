package com.unidocs.auth.credential.recovery.email;
import java.time.Clock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.*;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.core.task.support.ContextPropagatingTaskDecorator;
import io.micrometer.core.instrument.MeterRegistry;
@Configuration(proxyBeanMethods=false)
public class EmailRecoveryConfiguration {
    @Bean
    @ConditionalOnProperty(name="auth.password-recovery.email-enabled",havingValue="true")
    ThreadPoolTaskExecutor emailRecoveryExecutor() {
        ThreadPoolTaskExecutor executor=new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);executor.setMaxPoolSize(2);executor.setQueueCapacity(100);
        executor.setTaskDecorator(new ContextPropagatingTaskDecorator());
        executor.setThreadNamePrefix("password-recovery-mail-");executor.setDaemon(true);
        executor.setWaitForTasksToCompleteOnShutdown(false);
        return executor;
    }
    @Bean
    @ConditionalOnProperty(name="auth.password-recovery.email-enabled",havingValue="true")
    EmailRecoveryDelivery emailRecoveryDelivery(JavaMailSender sender,
            @Qualifier("emailRecoveryExecutor") ThreadPoolTaskExecutor executor,Clock clock,MeterRegistry metrics,
            @Value("${auth.password-recovery.mail-from}") String from) {
        if(from.isBlank() || from.contains("\r") || from.contains("\n"))
            throw new IllegalArgumentException("A valid recovery SMTP sender is required.");
        return new AsyncEmailRecoveryDelivery(new SmtpEmailRecoveryDelivery(sender,from),executor,clock,metrics);
    }
}
