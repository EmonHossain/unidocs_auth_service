package com.unidocs.auth.credential.recovery.email;
import java.time.Instant;
import java.util.UUID;
import jakarta.mail.Session;
import jakarta.mail.Multipart;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.javamail.JavaMailSender;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.*;
@ExtendWith(MockitoExtension.class)
class SmtpEmailRecoveryDeliveryTests {
    @Mock JavaMailSender sender;
    @Test void sendsPurposeBoundPlainAndHtmlFiveMinuteOneUseCodeWithoutSecretSubject() throws Exception {
        when(sender.createMimeMessage()).thenReturn(new MimeMessage((Session)null));
        UUID reference=UUID.randomUUID();Instant expiry=Instant.parse("2026-10-08T12:05:00Z");
        new SmtpEmailRecoveryDelivery(sender,"no-reply@example.com").deliver("user@example.com",reference,"012345",expiry);
        ArgumentCaptor<MimeMessage> capture=ArgumentCaptor.forClass(MimeMessage.class);verify(sender).send(capture.capture());
        MimeMessage message=capture.getValue();assertThat(message.getSubject()).contains("password").doesNotContain("012345");
        Multipart alternative=(Multipart)((Multipart)message.getContent()).getBodyPart(0).getContent();
        assertThat(alternative.getBodyPart(0).getContent().toString()).contains("012345","5 minutes",reference.toString());
        assertThat(alternative.getBodyPart(1).getContent().toString()).contains("012345","5 minutes","once",reference.toString(),expiry.toString()).doesNotContain("{{","http");
    }
}
