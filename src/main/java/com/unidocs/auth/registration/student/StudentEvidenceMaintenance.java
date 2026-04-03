package com.unidocs.auth.registration.student;
import java.time.Clock;
import java.sql.Timestamp;
import java.util.List;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.scheduling.annotation.Scheduled;
import io.micrometer.core.instrument.MeterRegistry;
@Component
@ConditionalOnProperty(name="registration.student.maintenance-enabled",havingValue="true",matchIfMissing=true)
public class StudentEvidenceMaintenance {
    private record Pending(String key,int attempts) { }
    private final JdbcTemplate jdbc;
    private final ObjectProvider<EvidenceStorage> storage;
    private final TransactionTemplate transactions;
    private final Clock clock;
    private final MeterRegistry metrics;
    public StudentEvidenceMaintenance(JdbcTemplate jdbc,ObjectProvider<EvidenceStorage> storage,PlatformTransactionManager manager,Clock clock,MeterRegistry metrics) {
        this.jdbc=jdbc;this.storage=storage;transactions=new TransactionTemplate(manager);this.clock=clock;this.metrics=metrics;
    }
    @Scheduled(fixedDelayString="${registration.student.maintenance-delay:60000}",initialDelayString="${registration.student.maintenance-delay:60000}")
    public void maintain() {
        transactions.executeWithoutResult(tx->{
            List<byte[]> ids=jdbc.query("SELECT id FROM student_admission WHERE status='EMAIL_PENDING' AND code_expires_at<=? ORDER BY id LIMIT 20 FOR UPDATE SKIP LOCKED",(rs,n)->rs.getBytes(1),Timestamp.from(clock.instant()));
            for(byte[] id:ids) {
                jdbc.update("INSERT IGNORE INTO admission_evidence_deletion(object_key,available_at) SELECT evidence_key,? FROM student_admission WHERE id=? AND evidence_key IS NOT NULL",Timestamp.from(clock.instant()),id);
                jdbc.update("UPDATE student_admission SET status='EXPIRED',password_hash='CONSUMED',code_hash='CONSUMED',version=version+1 WHERE id=?",id);
            }
        });
        EvidenceStorage provider=storage.getIfAvailable();if(provider==null)return;
        List<Pending> pending=jdbc.query("SELECT object_key,attempts FROM admission_evidence_deletion WHERE available_at<=? ORDER BY available_at,object_key LIMIT 20",(rs,n)->new Pending(rs.getString(1),rs.getInt(2)),Timestamp.from(clock.instant()));
        for(Pending item:pending) {
            try { provider.delete(item.key());jdbc.update("DELETE FROM admission_evidence_deletion WHERE object_key=?",item.key());metrics.counter("student.evidence.deletion","outcome","success").increment(); }
            catch(RuntimeException failure) { jdbc.update("UPDATE admission_evidence_deletion SET attempts=attempts+1,available_at=? WHERE object_key=?",Timestamp.from(clock.instant().plusSeconds(Math.min(3600,1L<<Math.min(12,item.attempts())))),item.key());metrics.counter("student.evidence.deletion","outcome","failure").increment(); }
        }
    }
}
