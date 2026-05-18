package com.unidocs.auth.student;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.List;
import java.util.UUID;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static com.unidocs.auth.group.persistence.GroupRuleRepository.uuid;

/** Removed owners cannot orphan private study containers. Existing members get the usual notice/copy window. */
@Component
public class StudentInstitutionMaintenance {
    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final OutboxRepository outbox;
    private final TransactionTemplate tx;
    public StudentInstitutionMaintenance(JdbcTemplate jdbc,Clock clock,OutboxRepository outbox,PlatformTransactionManager manager) {
        this.jdbc=jdbc;this.clock=clock;this.outbox=outbox;this.tx=new TransactionTemplate(manager);tx.setTimeout(5);
    }
    @Scheduled(fixedDelayString="${auth.student-institution.cleanup-delay-ms:60000}")
    public void closeRemovedOwnersGroups() {
        tx.executeWithoutResult(status->{
            jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR UPDATE",Long.class);
            List<Owned> groups=jdbc.query("""
                    SELECT g.id,g.organization_id,g.owner_account_id FROM iam_study_group g
                    JOIN iam_student_state s ON s.organization_id=g.organization_id AND s.account_id=g.owner_account_id
                    WHERE s.status IN('REMOVED_INTRUDER','REMOVED_TERMINATED') AND g.status='ACTIVE'
                    ORDER BY g.organization_id,g.id LIMIT 50 FOR UPDATE OF g
                    """,(row,index)->new Owned(uuid(row.getBytes(1)),uuid(row.getBytes(2)),uuid(row.getBytes(3))));
            for(Owned group:groups) {
                jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=? FOR UPDATE",Long.class,bytes(group.organization()));
                Timestamp now=Timestamp.from(clock.instant());
                jdbc.update("UPDATE iam_study_group SET status='PREPARING',deletion_requested_at=?,deletion_notice_seconds=604800,version=version+1 WHERE id=?",now,bytes(group.id()));
                jdbc.update("UPDATE organization SET authorization_version=authorization_version+1,updated_at=? WHERE id=?",now,bytes(group.organization()));
                Long version=jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?",Long.class,bytes(group.organization()));
                jdbc.update("INSERT INTO iam_student_audit VALUES(?,?,?,?,?,?,?,?)",bytes(UUID.randomUUID()),bytes(group.organization()),bytes(group.owner()),null,bytes(group.id()),"STUDY_REMOVED_OWNER_CLOSURE",version,now);
                outbox.lifecycle("ORGANIZATION",group.organization(),version,"STUDY_REMOVED_OWNER_CLOSURE",group.owner(),group.organization(),null,clock.instant());
            }
            if(!groups.isEmpty()) jdbc.update("UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL'");
        });
    }
    private record Owned(UUID id,UUID organization,UUID owner) { }
}
