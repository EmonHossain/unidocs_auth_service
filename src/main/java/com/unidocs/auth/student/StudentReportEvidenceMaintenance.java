package com.unidocs.auth.student;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static com.unidocs.auth.group.persistence.GroupRuleRepository.uuid;

/** The existing evidence-storage deletion worker performs external deletion after this transaction. */
@Component
public class StudentReportEvidenceMaintenance {
    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final TransactionTemplate tx;
    public StudentReportEvidenceMaintenance(JdbcTemplate jdbc,Clock clock,PlatformTransactionManager manager) {
        this.jdbc=jdbc;this.clock=clock;this.tx=new TransactionTemplate(manager);tx.setTimeout(5);
    }
    @Scheduled(fixedDelayString="${auth.student-report-evidence.cleanup-delay-ms:60000}")
    public void cleanup() {
        tx.executeWithoutResult(status->{
            jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR UPDATE",Long.class);
            List<Unused> rows=jdbc.query("SELECT e.id,e.object_key FROM iam_student_report_evidence e WHERE e.status IN('PENDING','READY') AND e.created_at<? AND NOT EXISTS(SELECT 1 FROM iam_student_report r WHERE r.evidence_reference=BIN_TO_UUID(e.id) OR r.review_evidence_reference=BIN_TO_UUID(e.id)) ORDER BY e.id LIMIT 50 FOR UPDATE",(row,index)->new Unused(uuid(row.getBytes(1)),row.getString(2)),Timestamp.from(clock.instant().minusSeconds(604800)));
            for(Unused row:rows) {
                jdbc.update("INSERT IGNORE INTO admission_evidence_deletion(object_key,available_at) VALUES(?,?)",row.key(),Timestamp.from(clock.instant()));
                jdbc.update("UPDATE iam_student_report_evidence SET status='EXPIRED' WHERE id=?",bytes(row.id()));
            }
        });
    }
    private record Unused(UUID id,String key) { @Override public String toString() { return "UnusedStudentEvidence[REDACTED]"; } }
}
