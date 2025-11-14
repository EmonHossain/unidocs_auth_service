package com.unidocs.auth.account.lifecycle;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

@Component
public class SmtpAccountNoticeDelivery implements AccountNoticeDelivery {
    private final ObjectProvider<JavaMailSender> sender;
    private final boolean enabled;
    private final String from;
    public SmtpAccountNoticeDelivery(ObjectProvider<JavaMailSender> sender,
            @Value("${auth.account-lifecycle.smtp-enabled:false}") boolean enabled,
            @Value("${auth.account-lifecycle.mail-from:no-reply@unidocs.local}") String from) {
        this.sender=sender;this.enabled=enabled;this.from=from;
    }
    public boolean enabled() { return enabled && sender.getIfAvailable()!=null; }
    public void deliver(String destination,LifecycleRepository.Notice notice) {
        if(!enabled()) throw new IllegalStateException("Security notice delivery unavailable.");
        SimpleMailMessage message=new SimpleMailMessage();message.setFrom(from);message.setTo(destination);
        message.setSubject("UniDocs account security notice: "+notice.code());
        String deadline=notice.deadline()==null?"":"\nDeadline (UTC): "+notice.deadline();
        message.setText("Account: "+notice.accountId()+"\nOrganization: "+notice.organizationId()+"\nAction: "+notice.code()
                +"\nReason: "+notice.reason()+deadline
                +"\nIssued at (UTC): "+notice.createdAt()+"\nSecurity notices do not grant account access.");
        sender.getObject().send(message);
    }
}
