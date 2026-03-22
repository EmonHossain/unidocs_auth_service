package com.unidocs.auth.registration.application;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.*;
import org.springframework.mail.javamail.JavaMailSender;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "registration.delivery.smtp.enabled", havingValue = "true")
public class SmtpVerificationConfiguration {
    @Bean
    @ConditionalOnMissingBean(VerificationDelivery.class)
    VerificationDelivery smtpVerificationDelivery(JavaMailSender sender,
            @Value("${registration.delivery.smtp.from}") String from) {
        if (from.isBlank() || from.contains("\r") || from.contains("\n")) {
            throw new IllegalArgumentException("A valid SMTP sender is required.");
        }
        return new SmtpVerificationDelivery(sender, from);
    }
}
