package com.unidocs.auth.registration.student;
import java.util.*;
import java.time.Instant;
import java.time.Duration;
import jakarta.validation.Validator;
import org.springframework.stereotype.Service;
import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.transaction.annotation.*;
import org.springframework.dao.DataIntegrityViolationException;
import com.unidocs.auth.registration.application.*;
import com.unidocs.auth.organization.application.OrganizationFailure;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.authorization.application.OrganizationSnapshotStore;
import org.springframework.security.crypto.password.PasswordEncoder;
@Service
@Transactional(propagation=Propagation.NEVER)
public class StudentAdmissionService {
    public record Page(List<StudentRequests.View> admissions,UUID nextCursor) { }
    private final StudentAdmissionRepository admissions;
    private final SessionAccess access;
    private final SessionRepository sessions;
    private final OrganizationRepository organizations;
    private final VerificationTokens codes;
    private final PasswordEncoder passwords;
    private final ObjectProvider<VerificationDelivery> delivery;
    private final ObjectProvider<EvidenceStorage> storage;
    private final OutboxRepository outbox;
    private final OrganizationSnapshotStore snapshots;
    private final Validator validator;
    private final com.unidocs.auth.student.StudentAuthorization students;
    public StudentAdmissionService(StudentAdmissionRepository admissions,SessionAccess access,SessionRepository sessions,OrganizationRepository organizations,
            VerificationTokens codes,PasswordEncoder passwords,ObjectProvider<VerificationDelivery> delivery,ObjectProvider<EvidenceStorage> storage,
            OutboxRepository outbox,OrganizationSnapshotStore snapshots,Validator validator,com.unidocs.auth.student.StudentAuthorization students) {
        this.students=students;
        this.admissions=admissions;this.access=access;this.sessions=sessions;this.organizations=organizations;this.codes=codes;this.passwords=passwords;this.delivery=delivery;this.storage=storage;this.outbox=outbox;this.snapshots=snapshots;this.validator=validator;
    }
    public StudentRequests.View apply(UUID sid,UUID subject,UUID org,StudentRequests.Apply command,StudentEvidence evidence) {
        validate(command);VerificationDelivery sender=delivery.getIfAvailable();if(sender==null)throw unavailable();
        String email=command.email().strip().toLowerCase(Locale.ROOT);
        String method=access.execute(sid,subject,c->applicant(c,org,command.accountId(),email,evidence));
        UUID id=UUID.randomUUID();String key=evidence==null?null:"admissions/"+org+"/"+id;
        EvidenceStorage evidenceStore=evidence==null?null:storage.getIfAvailable();if(evidence!=null&&evidenceStore==null)throw unavailable();
        String code=codes.generate();String codeHash=codes.hash(code);String hash=passwords.encode(command.password());
        if(evidenceStore!=null) { try { evidenceStore.put(key,evidence); } catch(RuntimeException failure) { throw unavailable(); } }
        StudentRequests.View response;
        try {
            response=access.execute(sid,subject,c->{
                String currentMethod=applicant(c,org,command.accountId(),email,evidence);if(!method.equals(currentMethod))throw denied();
                admissions.create(id,org,c,command.accountId(),email,method,hash,codeHash,c.now().plus(Duration.ofMinutes(5)),key,evidence==null?null:evidence.contentType());
                sessions.audit(c.owner().userId(),command.accountId(),sid,"STUDENT_ADMISSION_CREATED",c.now());
                outbox.lifecycle("STUDENT_ADMISSION",id,1,"STUDENT_ADMISSION_CREATED",command.accountId(),org,null,c.now());
                return admissions.find(id,false).orElseThrow().view();
            });
        } catch(RuntimeException failure) {
            if(evidenceStore!=null) { try { evidenceStore.delete(key); } catch(RuntimeException ignored) { /* private orphan, no access grant */ } }
            if(failure instanceof DataIntegrityViolationException)throw new OrganizationFailure(HttpStatus.CONFLICT);throw failure;
        }
        try { sender.deliver(email,id,code,response.codeExpiresAt()); } catch(RuntimeException failure) { throw unavailable(); }
        return response;
    }
    private String applicant(SessionAccess.Context c,UUID org,UUID account,String email,StudentEvidence evidence) {
        personal(c,account);admissions.lockUniversity(org);
        if(admissions.hasMembership(org,c.owner().userId()))throw new OrganizationFailure(HttpStatus.CONFLICT);
        if(admissions.instituteEmail(org,email)) { if(evidence!=null)throw badRequest();return "INSTITUTE_EMAIL"; }
        if(evidence==null||!organizations.verifiedEmail(c.owner().userId()).filter(email::equals).isPresent())throw badRequest();
        return "DOCUMENT";
    }
    public StudentRequests.View verify(UUID sid,UUID subject,UUID org,UUID id,StudentRequests.Verify command) {
        validate(command);StudentAdmissionRepository.Admission before=admissions.find(id,false).orElseThrow(StudentAdmissionService::denied);
        boolean matched="EMAIL_PENDING".equals(before.status())&&codes.matches(command.code(),before.codeHash());
        StudentRequests.View result=access.execute(sid,subject,c->{
            personal(c,command.accountId());admissions.lockUniversity(org);
            StudentAdmissionRepository.Admission a=owned(id,org,command.accountId(),c.owner().userId());
            // A consumed proof cannot create a second identity or membership on a retry.
            if(Set.of("PENDING_REVIEW","APPROVED").contains(a.status())) {
                return a.view();
            }
            if(!"EMAIL_PENDING".equals(a.status())||a.version()!=before.version())throw denied();
            if(!matched||!c.now().isBefore(a.expiresAt())) { admissions.failed(a,c.now());return admissions.find(id,false).orElseThrow().view(); }
            if("INSTITUTE_EMAIL".equals(a.method())) {
                if(!admissions.instituteEmail(org,a.email()))throw denied();approve(a,command.accountId(),c.now());
            } else admissions.transition(id,"PENDING_REVIEW");
            sessions.audit(c.owner().userId(),command.accountId(),sid,"STUDENT_ADMISSION_VERIFIED",c.now());
            StudentAdmissionRepository.Admission current=admissions.find(id,false).orElseThrow();
            outbox.lifecycle("STUDENT_ADMISSION",id,current.version(),"STUDENT_ADMISSION_VERIFIED",command.accountId(),org,null,c.now());return current.view();
        });
        if(!Set.of("PENDING_REVIEW","APPROVED").contains(result.status()))throw badRequest();snapshots.invalidate(org,admissions.version(org));return result;
    }
    public StudentRequests.View get(UUID sid,UUID subject,UUID org,UUID id,UUID account) {
        return access.execute(sid,subject,c->{
            personal(c,account);admissions.lockUniversity(org);return owned(id,org,account,c.owner().userId()).view();
        });
    }
    public StudentRequests.View review(UUID sid,UUID subject,UUID org,UUID id,StudentRequests.Review command) {
        validate(command);StudentAdmissionRepository.Admission before=admissions.find(id,false).filter(a->a.org().equals(org)).orElseThrow(StudentAdmissionService::denied);
        StudentRequests.View result=access.executeForGroups(sid,subject,List.of(before.group()),c->{
            curator(c,command.curatorAccountId(),org,false);
            StudentAdmissionRepository.Admission a=admissions.find(id,true).filter(v->v.org().equals(org)).orElseThrow(StudentAdmissionService::denied);
            if(!"PENDING_REVIEW".equals(a.status())||!admissions.applicantCurrent(a)||a.user().equals(c.owner().userId()))throw denied();
            if(command.approve())approve(a,command.curatorAccountId(),c.now());else admissions.transition(id,"REJECTED");
            admissions.review(a,command.curatorAccountId(),command.reason().strip());
            String event=command.approve()?"STUDENT_ADMISSION_APPROVED":"STUDENT_ADMISSION_REJECTED";
            sessions.audit(c.owner().userId(),command.curatorAccountId(),sid,event,c.now());
            StudentAdmissionRepository.Admission current=admissions.find(id,false).orElseThrow();outbox.lifecycle("STUDENT_ADMISSION",id,current.version(),event,a.applicant(),org,null,c.now());return current.view();
        });snapshots.invalidate(org,admissions.version(org));return result;
    }
    private void approve(StudentAdmissionRepository.Admission a,UUID actor,Instant now) {
        if(!admissions.applicantCurrent(a))throw denied();
        UUID account=admissions.approve(a,actor,now);StudentAdmissionRepository.Admission approved=admissions.find(a.id(),false).orElseThrow();long version=admissions.changed(a.org(),now);
        outbox.accountProvisioned(account,a.org(),approved.membership(),now);
        outbox.membershipActivated(a.org(),approved.membership(),account,a.id(),version,now);
    }
    public Page list(UUID sid,UUID subject,UUID org,UUID account,UUID after,int limit) {
        if(limit<1||limit>100)throw badRequest();return access.execute(sid,subject,c->{
            curator(c,account,org,false);List<StudentRequests.View> rows=admissions.views(org,after,limit+1);
            List<StudentRequests.View> page=rows.stream().limit(limit).toList();
            return new Page(page,rows.size()>limit?page.getLast().id():null);
        });
    }
    public StudentRequests.Evidence evidence(UUID sid,UUID subject,UUID org,UUID id,UUID account) {
        StudentAdmissionRepository.Admission a=access.execute(sid,subject,c->{
            curator(c,account,org,false);return admissions.find(id,true).filter(v->v.org().equals(org)&&v.evidenceKey()!=null&&"PENDING_REVIEW".equals(v.status())).orElseThrow(StudentAdmissionService::denied);
        });
        EvidenceStorage provider=storage.getIfAvailable();if(provider==null)throw unavailable();
        byte[] bytes;try { bytes=provider.get(a.evidenceKey()); } catch(RuntimeException failure) { throw unavailable(); }
        // Recheck scope after storage I/O so a revoked curator does not receive fetched bytes.
        access.execute(sid,subject,c->{curator(c,account,org,false);return true;});
        return new StudentRequests.Evidence(bytes,a.evidenceType());
    }
    public void domain(UUID sid,UUID subject,UUID org,StudentRequests.Domain command) {
        throw denied();
    }
    public void assignCurator(UUID sid,UUID subject,UUID org,StudentRequests.Curator command) {
        throw denied();
    }
    private void personal(SessionAccess.Context c,UUID account) {
        if(!sessions.accountType(c.session(),account).filter("PERSONAL"::equals).isPresent()) throw denied();
        SessionAccountGrant grant=sessions.liveGrant(c.session(),account,c.now()).orElseThrow(StudentAdmissionService::denied);
        if(!Set.of("LOGIN","PASSWORD").contains(grant.authMethod())||organizations.verifiedEmail(c.owner().userId()).isEmpty())throw denied();
    }
    private StudentAdmissionRepository.Admission owned(UUID id,UUID org,UUID account,UUID user) {
        return admissions.find(id,true).filter(a->a.org().equals(org)&&a.applicant().equals(account)&&a.user().equals(user)).orElseThrow(StudentAdmissionService::denied);
    }
    private void curator(SessionAccess.Context c,UUID account,UUID org,boolean adminOnly) {
        admissions.lockStudentPolicy();
        SessionAccountGrant grant=sessions.liveGrant(c.session(),account,c.now()).orElseThrow(StudentAdmissionService::denied);
        if(!Set.of("LOGIN","PASSWORD").contains(grant.authMethod()))throw denied();admissions.lockUniversity(org);
        OrganizationRepository.Visibility visible=organizations.visibility(account,grant.authMethod(),org).orElseThrow(StudentAdmissionService::denied);
        if(adminOnly) throw denied();
        try { students.require(c,account,org,null,"auth-service","student.admission.review"); }
        catch(com.unidocs.auth.authorization.application.OperationAuthorizationFailure failure) { throw new OrganizationFailure(failure.status()); }
    }
    private void validate(Object command) { if(command==null||!validator.validate(command).isEmpty())throw badRequest(); }
    public static OrganizationFailure denied() { return new OrganizationFailure(HttpStatus.FORBIDDEN); }
    private static OrganizationFailure badRequest() { return new OrganizationFailure(HttpStatus.BAD_REQUEST); }
    private static OrganizationFailure unavailable() { return new OrganizationFailure(HttpStatus.SERVICE_UNAVAILABLE); }
}
