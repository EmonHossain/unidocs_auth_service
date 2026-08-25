package com.unidocs.auth.organization.application;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SmtpInvitationDeliveryTests {
    @Mock JavaMailSender sender;
    @Test void deliversBoundProofToRecipient() {
        UUID organization=UUID.randomUUID(); UUID invitation=UUID.randomUUID();
        String proof=new InvitationTokens().generate();
        new SmtpInvitationDelivery(sender,"no-reply@example.com").deliver("member@example.com",organization,invitation,proof,Instant.parse("2026-10-03T12:00:00Z"));
        ArgumentCaptor<SimpleMailMessage> message=ArgumentCaptor.forClass(SimpleMailMessage.class); verify(sender).send(message.capture());
        assertThat(message.getValue().getTo()).containsExactly("member@example.com");
        assertThat(message.getValue().getText()).contains(organization.toString(),invitation.toString(),proof,"2026-10-03T12:00:00Z");
        assertThat(new InvitationTokens().hash(proof)).doesNotContain(proof).hasSize(64);
    }
}
