package com.unidocs.auth.organization.application;

import java.time.Instant;
import java.util.UUID;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

public class SmtpInvitationDelivery implements InvitationDelivery {
    private final JavaMailSender sender;
    private final String from;
    public SmtpInvitationDelivery(JavaMailSender sender,String from) { this.sender=sender; this.from=from; }
    @Override
    public void deliver(String email, UUID organization, UUID invitation, String token, Instant expiresAt) {
        SimpleMailMessage message=new SimpleMailMessage();
        message.setFrom(from); message.setTo(email); message.setSubject("Your UniDocs organization invitation");
        message.setText("Organization ID: "+organization+"\nInvitation ID: "+invitation+"\nInvitation token: "+token
                +"\nExpires at (UTC): "+expiresAt+"\nSign in with your verified invited email and submit this token in the invitation acceptance form."
                +"\nIf you did not expect this invitation, ignore this message.");
        sender.send(message);
    }
}
