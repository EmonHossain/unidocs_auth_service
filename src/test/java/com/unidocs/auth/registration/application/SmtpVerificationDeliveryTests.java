package com.unidocs.auth.registration.application;

import java.time.Instant;
import java.util.UUID;
import jakarta.mail.Session;
import jakarta.mail.Multipart;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.javamail.JavaMailSender;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SmtpVerificationDeliveryTests {
    @Mock JavaMailSender sender;
    @Test
    void sendsPlainAndHtmlCodeWithoutSecretsInSubjectOrUrls() throws Exception {
        when(sender.createMimeMessage()).thenReturn(new MimeMessage((Session) null));
        SmtpVerificationDelivery delivery = new SmtpVerificationDelivery(sender, "no-reply@example.com");
        UUID id = UUID.randomUUID();
        delivery.deliver("user@example.com", id, "012345", Instant.parse("2026-10-07T12:05:00Z"));
        ArgumentCaptor<MimeMessage> capture = ArgumentCaptor.forClass(MimeMessage.class);
        verify(sender).send(capture.capture());
        MimeMessage message = capture.getValue();
        assertThat(message.getSubject()).doesNotContain("012345");
        assertThat(message.getAllRecipients()[0].toString()).isEqualTo("user@example.com");
        Multipart mixed = (Multipart) message.getContent();
        Multipart alternative = (Multipart) mixed.getBodyPart(0).getContent();
        assertThat(alternative.getBodyPart(0).getContent().toString()).contains("012345", "5 minutes", id.toString());
        assertThat(alternative.getBodyPart(1).getContent().toString()).contains("012345", "5 minutes", "2026-10-07T12:05:00Z").doesNotContain("{{", "http");
    }
    @Test
    void escapesValuesInHtml() throws Exception {
        when(sender.createMimeMessage()).thenReturn(new MimeMessage((Session) null));
        new SmtpVerificationDelivery(sender, "no-reply@example.com").deliver("user@example.com", UUID.randomUUID(), "<script>", Instant.now());
        ArgumentCaptor<MimeMessage> capture = ArgumentCaptor.forClass(MimeMessage.class);
        verify(sender).send(capture.capture());
        Multipart alternative = (Multipart) ((Multipart) capture.getValue().getContent()).getBodyPart(0).getContent();
        assertThat(alternative.getBodyPart(1).getContent().toString()).contains("&lt;script&gt;").doesNotContain("<script>");
    }
}
