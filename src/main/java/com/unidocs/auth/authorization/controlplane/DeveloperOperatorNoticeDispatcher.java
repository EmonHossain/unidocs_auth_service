package com.unidocs.auth.authorization.controlplane;

import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Bounded durable security notices; SMTP runs only after the credential transaction commits. */
@Component
@EnableScheduling
@ConditionalOnProperty(name="auth.developer.operator.enabled",havingValue="true")
public class DeveloperOperatorNoticeDispatcher {
    private record Claim(UUID id,String email,String action,int attempts,UUID token) { }
    private final JdbcTemplate jdbc;
    private final ObjectProvider<JavaMailSender> mail;
    private final TransactionTemplate transactions;
    private final Clock clock;
    private final String sender;

    /** Builds the lease-based notice dispatcher.
     * @param jdbc notice persistence
     * @param mail configured mail sender
     * @param manager transaction manager
     * @param clock time source
     * @param sender configured sender address
     */
    public DeveloperOperatorNoticeDispatcher(JdbcTemplate jdbc,ObjectProvider<JavaMailSender> mail,
            PlatformTransactionManager manager,Clock clock,
            @Value("${auth.mail.from:no-reply@unidocs.local}") String sender) {
        this.jdbc=jdbc;this.mail=mail;this.transactions=new TransactionTemplate(manager);this.clock=clock;this.sender=sender;
    }

    /** Claims at most twenty pending notices, then sends and acknowledges outside the claim transaction. */
    @Scheduled(fixedDelayString="${auth.developer.notice-delay:10000}",initialDelayString="${auth.developer.notice-delay:10000}")
    public void dispatch() {
        JavaMailSender delivery=mail.getIfAvailable();if(delivery==null)return;
        List<Claim> claims=transactions.execute(status->{
            Instant now=clock.instant();UUID token=UUID.randomUUID();
            List<Claim> selected=jdbc.query("""
                    SELECT n.id,o.email,n.action_key,n.attempts FROM iam_developer_security_notice n
                    JOIN iam_developer_operator o ON o.id=n.operator_id AND o.email_verified=TRUE
                    WHERE n.status='PENDING' AND n.available_at<=? AND (n.lease_until IS NULL OR n.lease_until<=?)
                    ORDER BY n.available_at,n.id LIMIT 20 FOR UPDATE SKIP LOCKED
                    """,(row,index)->new Claim(uuid(row.getBytes(1)),row.getString(2),row.getString(3),row.getInt(4),token),
                    Timestamp.from(now),Timestamp.from(now));
            for(Claim claim:selected)jdbc.update("UPDATE iam_developer_security_notice SET claim_token=?,lease_until=? WHERE id=?",
                    bytes(token),Timestamp.from(now.plusSeconds(180)),bytes(claim.id()));
            return selected;
        });
        if(claims==null)return;
        for(Claim claim:claims) {
            Instant now=clock.instant();
            if(jdbc.update("UPDATE iam_developer_security_notice SET lease_until=? WHERE id=? AND claim_token=? AND lease_until>? AND status='PENDING'",
                    Timestamp.from(now.plusSeconds(30)),bytes(claim.id()),bytes(claim.token()),Timestamp.from(now))!=1)continue;
            try {
                SimpleMailMessage message=new SimpleMailMessage();message.setFrom(sender);message.setTo(claim.email());
                message.setSubject("UniDocs developer security notice");
                message.setText("A developer operator security action occurred: "+claim.action()+". If this was unexpected, contact the installation owner.");
                delivery.send(message);
                jdbc.update("UPDATE iam_developer_security_notice SET status='SENT',claim_token=NULL,lease_until=NULL WHERE id=? AND claim_token=? AND lease_until>?",
                        bytes(claim.id()),bytes(claim.token()),Timestamp.from(clock.instant()));
            } catch(RuntimeException failure) {
                long delay=Math.min(300,1L<<Math.min(8,claim.attempts()));
                jdbc.update("UPDATE iam_developer_security_notice SET attempts=attempts+1,available_at=?,claim_token=NULL,lease_until=NULL WHERE id=? AND claim_token=?",
                        Timestamp.from(clock.instant().plusSeconds(delay)),bytes(claim.id()),bytes(claim.token()));
            }
        }
    }
    private static UUID uuid(byte[] value) { ByteBuffer buffer=ByteBuffer.wrap(value);return new UUID(buffer.getLong(),buffer.getLong()); }
}
