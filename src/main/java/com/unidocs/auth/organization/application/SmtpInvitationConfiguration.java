package com.unidocs.auth.organization.application;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.*;
import org.springframework.mail.javamail.JavaMailSender;

@Configuration(proxyBeanMethods=false)
@ConditionalOnProperty(name="organization.invitation.smtp.enabled",havingValue="true")
public class SmtpInvitationConfiguration {
    @Bean
    InvitationDelivery smtpInvitationDelivery(JavaMailSender sender,@Value("${organization.invitation.smtp.from}") String from) {
        if(from.isBlank() || from.contains("\r") || from.contains("\n")) throw new IllegalArgumentException("A valid SMTP sender is required.");
        return new SmtpInvitationDelivery(sender,from);
    }
}
