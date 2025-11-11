package com.unidocs.auth.account.lifecycle;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import io.micrometer.core.instrument.MeterRegistry;
import static com.unidocs.auth.account.lifecycle.LifecycleRepository.*;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Fenced bounded claims; SMTP happens after the claim transaction commits. */
@Component
@org.springframework.transaction.annotation.Transactional(propagation=org.springframework.transaction.annotation.Propagation.NEVER)
public class AccountNoticeDispatcher {
    private record Claim(Notice notice,String email,UUID token,int attempts) { }
    private final JdbcTemplate jdbc;
    private final AccountNoticeDelivery delivery;
    private final Clock clock;
    private final TransactionTemplate transactions;
    private final MeterRegistry metrics;
    public AccountNoticeDispatcher(JdbcTemplate jdbc,AccountNoticeDelivery delivery,Clock clock,PlatformTransactionManager manager,MeterRegistry metrics) {
        this.jdbc=jdbc;this.delivery=delivery;this.clock=clock;this.metrics=metrics;transactions=new TransactionTemplate(manager);
        transactions.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
        transactions.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }
    @Scheduled(fixedDelayString="${auth.account-lifecycle.notice-delay:10000}",initialDelayString="${auth.account-lifecycle.notice-delay:10000}")
    public void dispatch() {
        if(!delivery.enabled()) return;
        List<Claim> claims=transactions.execute(tx->{
            Instant now=clock.instant();UUID token=UUID.randomUUID();
            List<Claim> rows=jdbc.query("""
                SELECT n.*,c.value email FROM account_security_notice n JOIN user_contact c ON c.user_id=n.user_id
                AND c.type='EMAIL' AND c.is_primary=true AND c.verified=true
                WHERE n.status='PENDING' AND n.available_at<=? AND (n.lease_until IS NULL OR n.lease_until<=?)
                ORDER BY n.available_at,n.id LIMIT 20 FOR UPDATE SKIP LOCKED
                """,(rs,n)->new Claim(new Notice(id(rs,"id"),id(rs,"account_id"),id(rs,"organization_id"),rs.getString("code"),
                        rs.getString("reason"),instant(rs,"deadline"),instant(rs,"created_at")),rs.getString("email"),token,rs.getInt("attempts")),time(now),time(now));
            for(Claim claim:rows) jdbc.update("UPDATE account_security_notice SET claim_token=?,lease_until=? WHERE id=?",bytes(token),time(now.plusSeconds(180)),bytes(claim.notice().id()));
            return rows;
        });
        for(Claim claim:claims) {
            // Renew before each network call: a batch can exceed the original lease during outages.
            if(jdbc.update("UPDATE account_security_notice SET lease_until=? WHERE id=? AND claim_token=? AND lease_until>? AND status='PENDING'",
                    time(clock.instant().plusSeconds(30)),bytes(claim.notice().id()),bytes(claim.token()),time(clock.instant()))!=1) continue;
            try {
                delivery.deliver(claim.email(),claim.notice());
                jdbc.update("UPDATE account_security_notice SET status='SENT',claim_token=NULL,lease_until=NULL WHERE id=? AND claim_token=? AND lease_until>?",
                        bytes(claim.notice().id()),bytes(claim.token()),time(clock.instant()));
                metrics.counter("account.notice.delivery","outcome","succeeded").increment();
            } catch(RuntimeException failure) {
                long delay=Math.min(300,1L<<Math.min(8,claim.attempts()));
                jdbc.update("UPDATE account_security_notice SET attempts=attempts+1,available_at=?,claim_token=NULL,lease_until=NULL WHERE id=? AND claim_token=?",
                        time(clock.instant().plusSeconds(delay)),bytes(claim.notice().id()),bytes(claim.token()));
                metrics.counter("account.notice.delivery","outcome","failed").increment();
            }
        }
    }
}
