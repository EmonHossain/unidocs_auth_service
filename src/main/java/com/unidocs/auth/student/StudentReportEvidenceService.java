package com.unidocs.auth.student;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.List;
import java.util.UUID;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.registration.student.EvidenceStorage;
import com.unidocs.auth.registration.student.StudentEvidence;
import com.unidocs.auth.session.application.SessionAccess;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static com.unidocs.auth.group.persistence.GroupRuleRepository.uuid;

/** Evidence stays in private storage. Metadata reservation and rechecks fence retries and revocation. */
@Service
@Transactional(propagation=Propagation.NEVER)
public class StudentReportEvidenceService {
    public record Download(byte[] bytes,String contentType) {
        public Download { bytes=bytes.clone(); }
        @Override public byte[] bytes() { return bytes.clone(); }
        @Override public String toString() { return "StudentReportEvidence[REDACTED]"; }
    }
    private record Metadata(UUID organization,UUID course,UUID report,UUID owner,String key,String type,String hash,String status) {
        @Override public String toString() { return "StudentEvidenceMetadata[REDACTED]"; }
    }
    private final JdbcTemplate jdbc;
    private final SessionAccess access;
    private final StudentAuthorization authorization;
    private final StudentWorkspaceService changes;
    private final ObjectProvider<EvidenceStorage> storage;
    private final Clock clock;
    public StudentReportEvidenceService(JdbcTemplate jdbc,SessionAccess access,StudentAuthorization authorization,StudentWorkspaceService changes,ObjectProvider<EvidenceStorage> storage,Clock clock) {
        this.jdbc=jdbc;this.access=access;this.authorization=authorization;this.changes=changes;this.storage=storage;this.clock=clock;
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public UUID upload(Jwt jwt,UUID organization,UUID account,UUID course,UUID report,UUID id,StudentEvidence evidence) {
        if(jwt==null||organization==null||account==null||course==null||id==null||evidence==null) throw StudentWorkspaceService.bad();
        String hash=hash(evidence.bytes());EvidenceStorage provider=storage.getIfAvailable();if(provider==null) throw unavailable();
        Metadata metadata=access.execute(sid(jwt),subject(jwt),c->{
            token(jwt);changes.fence(organization);admit(c,account,organization,course,report);
            List<Metadata> old=metadata(id);
            if(!old.isEmpty()) {
                Metadata prior=old.getFirst();
                if(!prior.organization().equals(organization)||!prior.course().equals(course)||!java.util.Objects.equals(prior.report(),report)||!prior.owner().equals(account)||!prior.hash().equals(hash)||!prior.type().equals(evidence.contentType())||prior.status().equals("EXPIRED")) throw StudentWorkspaceService.conflict();
                return prior;
            }
            Integer pending=jdbc.queryForObject("SELECT COUNT(*) FROM iam_student_report_evidence WHERE uploaded_by=? AND status IN('PENDING','READY') AND created_at>? AND NOT EXISTS(SELECT 1 FROM iam_student_report r WHERE r.evidence_reference=BIN_TO_UUID(iam_student_report_evidence.id) OR r.review_evidence_reference=BIN_TO_UUID(iam_student_report_evidence.id))",Integer.class,bytes(account),Timestamp.from(c.now().minusSeconds(604800)));
            if(pending!=null&&pending>=10) throw new com.unidocs.auth.authorization.application.OperationAuthorizationFailure(HttpStatus.TOO_MANY_REQUESTS,"STUDENT_EVIDENCE_LIMIT");
            String key="student-reports/"+organization+"/"+id;
            jdbc.update("INSERT INTO iam_student_report_evidence VALUES(?,?,?,?,?,?,?,?, 'PENDING',?)",bytes(id),bytes(organization),bytes(course),StudentWorkspaceService.nullable(report),bytes(account),key,evidence.contentType(),hash,Timestamp.from(c.now()));
            changes.changed(c,organization,account,id,"STUDENT_REPORT_EVIDENCE_RESERVED",account);token(jwt);
            return new Metadata(organization,course,report,account,key,evidence.contentType(),hash,"PENDING");
        });
        if(!metadata.status().equals("READY")) {
            try { provider.put(metadata.key(),evidence); } catch(RuntimeException failure) { throw unavailable(); }
            access.execute(sid(jwt),subject(jwt),c->{
                token(jwt);changes.fence(organization);admit(c,account,organization,course,report);
                Metadata current=metadata(id).stream().findFirst().orElseThrow(StudentAuthorization::denied);
                if(!current.hash().equals(hash)||current.status().equals("EXPIRED")) throw StudentAuthorization.denied();
                jdbc.update("UPDATE iam_student_report_evidence SET status='READY' WHERE id=?",bytes(id));
                changes.changed(c,organization,account,id,"STUDENT_REPORT_EVIDENCE_READY",account);token(jwt);return true;
            });
        }
        return id;
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public Download download(Jwt jwt,UUID organization,UUID account,UUID report,UUID evidence) {
        Metadata metadata=access.execute(sid(jwt),subject(jwt),c->{
            token(jwt);authorization.require(c,account,organization,null,"auth-service","student.report.review");return reviewedEvidence(organization,report,evidence);
        });
        EvidenceStorage provider=storage.getIfAvailable();if(provider==null) throw unavailable();
        byte[] content;try { content=provider.get(metadata.key()); } catch(RuntimeException failure) { throw unavailable(); }
        if(content.length>StudentEvidence.MAX_BYTES||!hash(content).equals(metadata.hash())) throw unavailable();
        access.execute(sid(jwt),subject(jwt),c->{
            token(jwt);authorization.require(c,account,organization,null,"auth-service","student.report.review");reviewedEvidence(organization,report,evidence);token(jwt);return true;
        });
        return new Download(content,metadata.type());
    }
    private Metadata reviewedEvidence(UUID organization,UUID report,UUID evidence) {
        boolean bound=Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM iam_student_report r WHERE r.organization_id=? AND r.id=? AND (r.evidence_reference=? OR r.review_evidence_reference=?))",Boolean.class,bytes(organization),bytes(report),evidence.toString(),evidence.toString()));
        Metadata current=metadata(evidence).stream().findFirst().orElseThrow(StudentAuthorization::denied);
        if(!bound||!current.organization().equals(organization)||!current.status().equals("READY")) throw StudentAuthorization.denied();return current;
    }
    private void admit(SessionAccess.Context c,UUID account,UUID organization,UUID course,UUID report) {
        if(report==null) authorization.require(c,account,organization,course,"auth-service","student.report.submit");
        else {
            authorization.require(c,account,organization,null,"auth-service","student.report.review");
            if(!Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM iam_student_report WHERE id=? AND organization_id=? AND course_id=? AND status IN('SUBMITTED','REVIEWED'))",Boolean.class,bytes(report),bytes(organization),bytes(course)))) throw StudentAuthorization.denied();
        }
    }
    private List<Metadata> metadata(UUID id) {
        return jdbc.query("SELECT * FROM iam_student_report_evidence WHERE id=?",(row,index)->new Metadata(uuid(row.getBytes("organization_id")),uuid(row.getBytes("course_id")),uuid(row.getBytes("report_id")),uuid(row.getBytes("uploaded_by")),row.getString("object_key"),row.getString("content_type"),row.getString("content_hash"),row.getString("status")),bytes(id));
    }
    private void token(Jwt jwt) { if(jwt==null||jwt.getExpiresAt()==null||!clock.instant().isBefore(jwt.getExpiresAt())) throw new AuthenticationFailure(); }
    private static UUID sid(Jwt jwt) { if(jwt==null) throw new AuthenticationFailure();return UUID.fromString(jwt.getClaimAsString("sid")); }
    private static UUID subject(Jwt jwt) { return UUID.fromString(jwt.getSubject()); }
    private static String hash(byte[] content) {
        try { return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(content)); }
        catch(java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    private static com.unidocs.auth.authorization.application.OperationAuthorizationFailure unavailable() { return new com.unidocs.auth.authorization.application.OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE,"STUDENT_EVIDENCE_UNAVAILABLE"); }
}
