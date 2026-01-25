package com.unidocs.auth.group.application;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import com.unidocs.auth.group.api.GroupRuleRequests;
import com.unidocs.auth.group.domain.*;
import com.unidocs.auth.group.persistence.*;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.persistence.SessionRepository;
import static com.unidocs.auth.group.application.GroupRuleService.*;

@Service
@Transactional(propagation=Propagation.NEVER)
public class AcademicEnrollmentService {
    public record EnrollmentView(UUID id,UUID memberAccountId,UUID semesterId,long version,List<UUID> courseGroupIds) { }
    public record Semesters(List<AcademicRepository.Semester> semesters,UUID nextCursor) { }
    private record Result(EnrollmentView response,long organizationVersion) { }
    private final AcademicRepository academics;
    private final GroupRuleRepository rules;
    private final GroupRepository groups;
    private final GroupMembershipRepository members;
    private final OrganizationRepository organizations;
    private final GroupAuthority authority;
    private final GroupRuleService changes;
    private final SessionAccess access;
    private final SessionRepository sessions;
    private final OutboxRepository outbox;
    public AcademicEnrollmentService(AcademicRepository academics,GroupRuleRepository rules,GroupRepository groups,GroupMembershipRepository members,
            OrganizationRepository organizations,GroupAuthority authority,GroupRuleService changes,SessionAccess access,SessionRepository sessions,OutboxRepository outbox) {
        this.academics=academics;this.rules=rules;this.groups=groups;this.members=members;this.organizations=organizations;this.authority=authority;
        this.changes=changes;this.access=access;this.sessions=sessions;this.outbox=outbox;
    }
    public AcademicRepository.Semester createSemester(UUID sid,UUID subject,UUID organization,GroupRuleRequests.Semester command) {
        changes.validate(command);
        if(!databaseTime(command.startsAt())||!databaseTime(command.endsAt())||!command.endsAt().isAfter(command.startsAt()))throw badRequest();
        return access.execute(sid,subject,context->{
            GroupAuthority.Access actor=authority.require(context,command.accountId(),organization,null,true,false,true);
            if(!rules.university(organization))throw badRequest();
            AcademicRepository.Semester existing=academics.semester(organization,command.code()).orElse(null);
            if(existing!=null) {
                if(!existing.startsAt().equals(command.startsAt())||!existing.endsAt().equals(command.endsAt()))throw conflict();
                return existing;
            }
            if(!command.endsAt().isAfter(context.now()))throw badRequest();
            AcademicRepository.Semester semester=new AcademicRepository.Semester(UUID.randomUUID(),command.code(),command.startsAt(),command.endsAt());
            academics.createSemester(organization,semester);
            sessions.audit(context.owner().userId(),command.accountId(),sid,"ACADEMIC_SEMESTER_CREATED",context.now());
            outbox.lifecycle("ACADEMIC_SEMESTER",semester.id(),1,"ACADEMIC_SEMESTER_CREATED",command.accountId(),organization,null,context.now());
            sessions.touch(context.session(),actor.grant(),context.now());return semester;
        });
    }
    public Semesters semesters(UUID sid,UUID subject,UUID organization,UUID account,UUID after,int limit) {
        if(limit<1||limit>100)throw badRequest();
        return access.execute(sid,subject,context->{
            authority.require(context,account,organization,null,false,false,true);
            List<AcademicRepository.Semester> rows=academics.semesters(organization,after,limit+1);
            return new Semesters(rows.stream().limit(limit).toList(),rows.size()>limit?rows.get(limit-1).id():null);
        });
    }
    public EnrollmentView replace(UUID sid,UUID subject,UUID organization,GroupRuleRequests.Enrollment command) {
        changes.validate(command);
        if(command.courseGroupIds().stream().distinct().count()!=command.courseGroupIds().size())throw badRequest();
        String fingerprint=hash(command.memberAccountId()+"\n"+command.semesterId()+"\n"+command.expectedVersion()+"\n"+
                command.courseGroupIds().stream().map(UUID::toString).sorted().toList());
        UUID targetGroup=members.accountGroup(command.memberAccountId()).orElseThrow(GroupAuthority::denied);
        Result result=access.executeForGroups(sid,subject,List.of(targetGroup),context->{
            GroupAuthority.Access actor=authority.require(context,command.accountId(),organization,null,true,false,true);
            if(!rules.university(organization))throw badRequest();
            UUID targetUser=sessions.owner(targetGroup).orElseThrow(GroupAuthority::denied).userId();
            if(targetUser.equals(context.owner().userId()))throw GroupAuthority.denied();
            OrganizationRepository.Visibility target=organizations.visibility(command.memberAccountId(),"PASSWORD",organization).orElseThrow(GroupAuthority::denied);
            AcademicRepository.Semester semester=academics.semester(organization,command.semesterId()).orElseThrow(GroupRuleService::badRequest);
            if(!semester.endsAt().isAfter(context.now()))throw badRequest();
            AcademicRepository.Enrollment old=academics.enrollment(target.membershipId()).orElse(null);
            if(old!=null && old.request().equals(command.requestId())) {
                if(!old.actor().equals(command.accountId())||!old.fingerprint().equals(fingerprint))throw conflict();
                return new Result(view(old),0);
            }
            if(command.expectedVersion()!=(old==null?0:old.version()))throw conflict();
            List<com.unidocs.auth.group.api.GroupResponse> courses=groups.findAll(organization,command.courseGroupIds());
            List<GroupRule> policies=rules.findAll(organization,command.courseGroupIds());
            if(courses.size()!=command.courseGroupIds().size() || policies.size()!=command.courseGroupIds().size()
                    || courses.stream().anyMatch(course->course.type()!=Group.Type.COURSE)
                    || policies.stream().anyMatch(rule->rule.joining()!=GroupRule.Joining.COURSE_ENROLLMENT || !semester.id().equals(rule.semesterId())))throw badRequest();
            List<UUID> previous=academics.courseMemberships(organization,target.membershipId(),101);
            if(previous.size()>100)throw conflict();
            AcademicRepository.Enrollment current=new AcademicRepository.Enrollment(old==null?UUID.randomUUID():old.id(),command.memberAccountId(),
                    target.membershipId(),semester.id(),old==null?1:old.version()+1,command.accountId(),command.requestId(),fingerprint);
            academics.save(organization,current,context.now());
            long version=members.advanceOrganization(organization,context.now());
            for(UUID id:previous) {
                members.revoke(id,command.accountId(),context.now());
                GroupMembership revoked=members.find(organization,academics.membershipGroup(id),id).orElseThrow();
                outbox.groupMembershipChanged(revoked,version,"GROUP_MEMBER_REVOKED",context.now(),false);
            }
            for(UUID course:command.courseGroupIds()) {
                GroupMembership member=new GroupMembership(UUID.randomUUID(),organization,course,command.memberAccountId(),target.membershipId(),"student",
                        GroupMembership.MembershipType.TEMPORARY,GroupMembership.Source.COURSE_ENROLLMENT,current.id().toString(),GroupMembership.Status.ACTIVE,
                        semester.startsAt(),semester.endsAt(),1,context.now(),context.now());
                members.create(member,command.accountId(),UUID.randomUUID(),fingerprint,current.version());
                outbox.groupMembershipChanged(member,version,"GROUP_MEMBER_ASSIGNED",context.now(),false);
            }
            sessions.audit(context.owner().userId(),command.accountId(),sid,"COURSE_ENROLLMENT_REPLACED",context.now());
            outbox.lifecycle("STUDENT_ENROLLMENT",current.id(),current.version(),"COURSE_ENROLLMENT_REPLACED",command.memberAccountId(),organization,null,context.now());
            outbox.lifecycle("ORGANIZATION",organization,version,"ORGANIZATION_GROUP_MEMBERSHIP_CHANGED",command.memberAccountId(),organization,null,context.now());
            sessions.touch(context.session(),actor.grant(),context.now());return new Result(view(current),version);
        });
        changes.invalidate(organization,result.organizationVersion());return result.response();
    }
    public EnrollmentView mine(UUID sid,UUID subject,UUID organization,UUID account) {
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision=
                authority.checkNavigationCanary(sid,subject,account,organization,null);
        return access.execute(sid,subject,context->{
            GroupAuthority.Access actor=authority.require(context,account,organization,null,false,false,false,true,decision);
            return view(academics.enrollment(actor.visibility().membershipId()).orElseThrow(GroupAuthority::denied));
        });
    }
    private EnrollmentView view(AcademicRepository.Enrollment row) {
        return new EnrollmentView(row.id(),row.accountId(),row.semesterId(),row.version(),academics.courseIds(row.anchor(),row.version()));
    }
    private static boolean databaseTime(Instant instant) {
        return instant!=null && instant.getNano()%1000==0 && !instant.isBefore(Instant.parse("1000-01-01T00:00:00Z")) && instant.isBefore(Instant.parse("+10000-01-01T00:00:00Z"));
    }
}
