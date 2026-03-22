package com.unidocs.auth.registration.application;

import java.time.Instant;
import java.util.UUID;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.web.util.HtmlUtils;

public class SmtpVerificationDelivery implements VerificationDelivery {
    private final JavaMailSender sender;
    private final String from;
    private final String template;
    public SmtpVerificationDelivery(JavaMailSender sender, String from) {
        this.sender = sender;
        this.from = from;
        try {
            template = new ClassPathResource("mail/verification.html").getContentAsString(StandardCharsets.UTF_8);
        } catch (IOException failure) {
            throw new IllegalStateException("Verification email template is unavailable.", failure);
        }
    }
    @Override
    public void deliver(String destination, UUID registrationId, String token, Instant expiresAt) {
        try {
            MimeMessage message = sender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, MimeMessageHelper.MULTIPART_MODE_MIXED, StandardCharsets.UTF_8.name());
            helper.setFrom(from);
            helper.setTo(destination);
            helper.setSubject("Your UniDocs verification code");
            String plain = "Your UniDocs verification code: " + token
                    + "\nValid for 5 minutes. Expires at (UTC): " + expiresAt
                    + "\nReference: " + registrationId
                    + "\nIf you did not request this, ignore this email. Do not share your code.";
            String html = template.replace("{{code}}", HtmlUtils.htmlEscape(token))
                    .replace("{{expiresAt}}", HtmlUtils.htmlEscape(expiresAt.toString()))
                    .replace("{{registrationId}}", registrationId.toString());
            helper.setText(plain, html);
            sender.send(message);
        } catch (MessagingException failure) {
            throw new IllegalStateException("Verification email could not be prepared.");
        }
    }
}
