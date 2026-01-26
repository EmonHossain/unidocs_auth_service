package com.unidocs.auth.group.application;

import java.util.Set;
import java.util.UUID;
import java.util.Objects;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import com.unidocs.auth.group.persistence.GroupRepository;
import com.unidocs.auth.group.persistence.GroupRuleRepository;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;

@Component
public class GroupAuthority {
    public record Access(SessionAccountGrant grant,OrganizationRepository.Visibility visibility) { }
    private final SessionRepository sessions;
    private final GroupRepository groups;
    private final GroupRuleRepository rules;
    private final OrganizationRepository organizations;
    private final com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional;
    private final com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary;
    @Autowired
    public GroupAuthority(SessionRepository sessions,GroupRepository groups,GroupRuleRepository rules,OrganizationRepository organizations,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional,
            ObjectProvider<com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary> canaryProvider) {
        this(sessions,groups,rules,organizations,professional,canaryProvider.getIfAvailable());
    }
    public GroupAuthority(SessionRepository sessions,GroupRepository groups,GroupRuleRepository rules,OrganizationRepository organizations,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional) {
        this(sessions,groups,rules,organizations,professional,(com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary)null);
    }
    private GroupAuthority(SessionRepository sessions,GroupRepository groups,GroupRuleRepository rules,OrganizationRepository organizations,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary) {
        this.professional=professional;
        this.canary=canary;
        this.sessions=sessions;this.groups=groups;this.rules=rules;this.organizations=organizations;
    }
    public Access require(SessionAccess.Context context,UUID account,UUID organization,UUID group,boolean mutation,boolean manager,boolean orgAdmin) {
        return require(context,account,organization,group,mutation,manager,orgAdmin,true);
    }
    public Access require(SessionAccess.Context context,UUID account,UUID organization,UUID group,boolean mutation,boolean manager,boolean orgAdmin,boolean activeGroup) {
        return require(context,account,organization,group,mutation,manager,orgAdmin,activeGroup,null);
    }
    /**
     * Validates current account admission and completes selected graph revalidation before returning access.
     * @param context locked session context
     * @param account selected account
     * @param organization verified tenant
     * @param group optional group scope
     * @param mutation whether organization mutation locks are required
     * @param manager whether scope-management authority is required
     * @param orgAdmin whether assignment authority is required
     * @param activeGroup whether legacy paths require an active group
     * @param decision external graph preflight evidence, if selected
     * @return current grant and organization visibility
     * @throws GroupFailure when admission or scope access is denied
     * @throws com.unidocs.auth.authorization.application.OperationAuthorizationFailure when graph evidence fails
     */
    public Access require(SessionAccess.Context context,UUID account,UUID organization,UUID group,boolean mutation,boolean manager,
            boolean orgAdmin,boolean activeGroup,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision) {
        return requireInternal(context,account,organization,group,mutation,manager,orgAdmin,activeGroup,decision,true);
    }
    /**
     * Keeps catalog admission distinct from content navigation while retaining its SQL admission guard.
     * @param context locked session context
     * @param account selected account
     * @param organization verified tenant
     * @param group optional group scope
     * @param mutation whether mutation locks are required
     * @param manager whether team management is required
     * @param orgAdmin whether assignment authority is required
     * @param activeGroup whether the group must be active
     * @param decision request-local graph evidence
     * @param navigation whether this is a content navigation entry point
     * @return current account grant and visibility
     */
    private Access requireInternal(SessionAccess.Context context,UUID account,UUID organization,UUID group,boolean mutation,
            boolean manager,boolean orgAdmin,boolean activeGroup,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision,boolean navigation) {
        if (decision != null && canary == null) throw new GroupFailure(HttpStatus.SERVICE_UNAVAILABLE);
        SessionAccountGrant grant=sessions.liveGrant(context.session(),account,context.now()).orElseThrow(GroupAuthority::denied);
        if((mutation||manager||orgAdmin) && !Set.of("LOGIN","PASSWORD").contains(grant.authMethod())) throw denied();
        if(!groups.lockOrganization(organization,mutation)) throw denied();
        OrganizationRepository.Visibility visible=organizations.visibility(account,grant.authMethod(),organization).orElseThrow(GroupAuthority::denied);
        // University mutations use the student catalog/self-join capability, never legacy admin/curator paths.
        if(rules.university(organization)) throw denied();
        if(professional.professional(organization)) {
            String operation=orgAdmin?"organization.group.assign":manager?"team.access.update":"workspace.read";
            if(canary!=null && (manager || orgAdmin))canary.requireDecision(organization,group,operation,decision);
            if(canary!=null && navigation && !manager && !orgAdmin)
                canary.requireContentDecision(organization,group,operation,false,decision);
            if(decision!=null && decision.enforcing()) {
                if(!operation.equals(decision.operation()) || !Objects.equals(group,decision.group())) throw denied();
            } else professionalGrant(context,account,organization,group,manager||orgAdmin?"auth-service":"document-service",operation);
            if (decision != null) canary.revalidate(decision, context, account, organization);
            return new Access(grant,visible);
        }
        boolean admin=visible.role()==OrganizationMembership.Role.OWNER || visible.role()==OrganizationMembership.Role.ADMIN;
        if(orgAdmin && !admin && !(group==null && organizations.instituteCurator(organization,visible.membershipId()))) throw denied();
        if(activeGroup && group!=null && groups.find(organization,group).isEmpty()) throw denied();
        if(manager && !admin && (group==null || !rules.effective(organization,group,visible.membershipId(),context.now(),true))) throw denied();
        return new Access(grant,visible);
    }
    public Access requireCatalog(SessionAccess.Context context,UUID account,UUID organization,UUID group,boolean mutation) {
        return requireCatalog(context,account,organization,group,mutation,null);
    }
    /**
     * Completes catalog-management authorization without relying on a second caller-side graph check.
     * @param context locked session context
     * @param account selected account
     * @param organization verified tenant
     * @param group managed group
     * @param mutation whether mutation locks are required
     * @param decision external catalog preflight evidence, if selected
     * @return current account grant and organization visibility
     * @throws GroupFailure when admission or catalog access is denied
     * @throws com.unidocs.auth.authorization.application.OperationAuthorizationFailure when graph evidence fails
     */
    public Access requireCatalog(SessionAccess.Context context,UUID account,UUID organization,UUID group,boolean mutation,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision) {
        if (decision != null && canary == null) throw new GroupFailure(HttpStatus.SERVICE_UNAVAILABLE);
        Access actor=requireInternal(context,account,organization,group,mutation,false,false,true,null,false);
        if(professional.professional(organization)) {
            if(canary!=null)canary.requireDecision(organization,null,"organization.group.create",decision);
            if(decision==null || !decision.enforcing())
                professionalGrant(context,account,organization,null,"auth-service","organization.group.create");
            if (decision != null) canary.revalidate(decision, context, account, organization);
            return actor;
        }
        boolean admin=actor.visibility().role()==OrganizationMembership.Role.OWNER || actor.visibility().role()==OrganizationMembership.Role.ADMIN;
        com.unidocs.auth.group.domain.Group.Type type=groups.find(organization,group).orElseThrow(GroupAuthority::denied).group().type();
        boolean curator=(type==com.unidocs.auth.group.domain.Group.Type.COURSE || type==com.unidocs.auth.group.domain.Group.Type.DEPARTMENT)
                && organizations.instituteCurator(organization,actor.visibility().membershipId());
        if(!admin&&!curator&&!rules.effective(organization,group,actor.visibility().membershipId(),context.now(),true))throw denied();
        return actor;
    }
    public static GroupFailure denied() { return new GroupFailure(HttpStatus.FORBIDDEN); }
    /**
     * Obtains the strict SQL/graph intersection before entering a navigation transaction.
     * @param sid authenticated session
     * @param subject authenticated login account
     * @param account selected account
     * @param organization verified tenant
     * @param group optional owning group
     * @return request-local graph evidence, or null outside the selected cohort
     * @throws com.unidocs.auth.authorization.application.OperationAuthorizationFailure when denied or unavailable
     */
    public com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision checkNavigationCanary(
            UUID sid,UUID subject,UUID account,UUID organization,UUID group) {
        return canary!=null && canary.applies(organization,"workspace.read")
                ? canary.checkContent(sid,subject,account,organization,group,"workspace.read",false):null;
    }
    /**
     * Checks the scoped team-management permission before a transactional group command.
     * @param sid authenticated session ID
     * @param subject authenticated user ID
     * @param account selected account ID
     * @param organization verified organization ID
     * @param group verified group ID
     * @return graph decision, or null outside the selected cohort
     */
    public com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision checkManagerCanary(
            UUID sid,UUID subject,UUID account,UUID organization,UUID group) {
        return canary!=null && canary.applies(organization,"team.access.update")
                ? canary.check(sid,subject,account,organization,group,"team.access.update"):null;
    }
    /**
     * Explicitly revalidates existing integrations; manager/catalog require methods already complete this check.
     * @param decision earlier graph decision, or null outside the cohort
     * @param context current session context
     * @param account selected account ID
     * @param organization verified organization ID
     */
    public void revalidateManagerCanary(
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision,
            SessionAccess.Context context,UUID account,UUID organization) {
        if(decision!=null)canary.revalidate(decision,context,account,organization);
    }
    private void professionalGrant(SessionAccess.Context context,UUID account,UUID organization,UUID group,String service,String operation) {
        try { professional.require(context,account,organization,group,service,operation); }
        catch(com.unidocs.auth.authorization.application.OperationAuthorizationFailure failure) { throw new GroupFailure(failure.status()); }
    }
}
