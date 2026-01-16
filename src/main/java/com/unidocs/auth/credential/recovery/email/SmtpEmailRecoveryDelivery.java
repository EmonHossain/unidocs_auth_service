package com.unidocs.auth.credential.recovery.email;
import java.time.Instant;
import java.util.UUID;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.web.util.HtmlUtils;

public class SmtpEmailRecoveryDelivery implements EmailRecoveryDelivery {
    private final JavaMailSender sender;
    private final String from;
    private final String template;
    public SmtpEmailRecoveryDelivery(JavaMailSender sender,String from) {
        this.sender=sender;this.from=from;
        try { template=new ClassPathResource("mail/password-recovery.html").getContentAsString(StandardCharsets.UTF_8); }
        catch(IOException failure) { throw new IllegalStateException("Recovery template unavailable."); }
    }
    @Override public void deliver(String email,UUID recoveryId,String code,Instant expiresAt) {
        try {
            MimeMessage message=sender.createMimeMessage();
            MimeMessageHelper helper=new MimeMessageHelper(message,MimeMessageHelper.MULTIPART_MODE_MIXED,StandardCharsets.UTF_8.name());
            helper.setFrom(from);helper.setTo(email);helper.setSubject("Reset your UniDocs password");
            String text="Your password reset code: "+code+"\nValid for 5 minutes. Expires at (UTC): "+expiresAt
                    +"\nRecovery reference: "+recoveryId+"\nIf you did not request this, ignore this email. Never share this code.";
            helper.setText(text,template.replace("{{code}}",HtmlUtils.htmlEscape(code))
                    .replace("{{expiresAt}}",HtmlUtils.htmlEscape(expiresAt.toString())).replace("{{recoveryId}}",recoveryId.toString()));
            sender.send(message);
        } catch(MessagingException failure) { throw new IllegalStateException("Recovery email could not be prepared."); }
    }
}
