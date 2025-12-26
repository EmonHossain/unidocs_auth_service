package com.unidocs.auth.authorization.controlplane;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import com.unidocs.auth.authorization.application.ProfessionalAuthorizationService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Bounded, redacted operator inspection through Auth rather than a raw tuple browser. */
@Service
@ConditionalOnProperty(name="auth.developer.operator.enabled",havingValue="true")
public class DeveloperInspectionService {
    public record Request(String password,String secondFactor,String kind,UUID organizationId,
            UUID targetAccountId,UUID operationId,UUID after,int limit) {
        @Override public String toString() { return "Request[REDACTED]"; }
    }
    public record Audit(UUID id,String action,UUID aggregateId,Long version,Instant occurredAt) { }
    public record Relationship(UUID membershipId,String organizationRole,List<UUID> groupIds) { }
    public record Projection(long requiredRevision,long appliedRevision,long requiredSourceVersion,
            long appliedSourceVersion,String status,String lastErrorCode) { }
    public record Explanation(String decision,String reasonCode,long organizationVersion) { }
    public record Inspection(String kind,List<Audit> audit,Relationship relationship,Projection projection,
            Explanation explanation,String expectedSchemaVersion,boolean canaryEnabled,boolean canarySelected) { }
    private final DeveloperOperatorGate gate;
    private final ProfessionalAuthorizationService authorization;
    private final JdbcTemplate jdbc;
    private final boolean canaryEnabled;
    private final Set<UUID> canaryOrganizations;

    /** Wires operator-gated, server-owned inspection data.
     * @param gate independent operator proof gate
     * @param authorization current organization evaluator
     * @param jdbc authoritative IAM records
     * @param canaryEnabled server-owned canary flag
     * @param canaryIds server-owned canary cohort
     */
    public DeveloperInspectionService(DeveloperOperatorGate gate,ProfessionalAuthorizationService authorization,
            JdbcTemplate jdbc,@Value("${auth.spicedb.canary.enabled:false}") boolean canaryEnabled,
            @Value("${auth.spicedb.canary.organization-ids:}") String canaryIds) {
        this.gate=gate;this.authorization=authorization;this.jdbc=jdbc;this.canaryEnabled=canaryEnabled;
        this.canaryOrganizations=canaryIds.isBlank()?Set.of():List.of(canaryIds.split(",")).stream()
                .map(String::strip).filter(value->!value.isEmpty()).map(UUID::fromString).collect(Collectors.toUnmodifiableSet());
    }

    /** Consumes one operator factor to inspect only a bounded registered view.
     * @param jwt verified operator token
     * @param request requested redacted view and current proof
     * @return no-store inspection response
     */
    public Inspection inspect(Jwt jwt,Request request) {
        if(request==null || request.kind()==null || request.limit()<1 || request.limit()>100)throw bad();
        return gate.execute(jwt,request.password(),request.secondFactor(),null,context->switch(request.kind()) {
            case "audit" -> new Inspection("audit",jdbc.query("SELECT id,action_key,aggregate_id,aggregate_version,occurred_at FROM iam_developer_operator_audit WHERE operator_id=? AND id>? ORDER BY id LIMIT ?",
                    (row,index)->new Audit(uuid(row.getBytes(1)),row.getString(2),optional(row.getBytes(3)),
                            row.getObject(4)==null?null:row.getLong(4),row.getTimestamp(5).toInstant()),
                    bytes(context.operatorId()),bytes(request.after()==null?new UUID(0,0):request.after()),request.limit()),
                    null,null,null,null,false,false);
            case "relationships" -> relationships(request);
            case "projection" -> projection(request);
            case "explanation" -> explanation(request);
            default -> throw bad();
        });
    }

    private Inspection relationships(Request request) {
        UUID organization=required(request.organizationId());UUID target=required(request.targetAccountId());
        activeOrganization(organization);
        List<Relationship> members=jdbc.query("""
                SELECT m.id,m.role FROM organization_membership m JOIN user_account a ON a.id=m.account_id
                WHERE m.organization_id=? AND m.account_id=? AND m.status='ACTIVE' AND a.organization_id=m.organization_id
                    AND a.status='ACTIVE' AND a.type IN('COMPANY','CUSTOM')
                """,(row,index)->new Relationship(uuid(row.getBytes(1)),row.getString(2),List.of()),bytes(organization),bytes(target));
        if(members.size()!=1)throw denied();
        List<UUID> groups=jdbc.query("SELECT group_id FROM group_membership WHERE organization_id=? AND account_id=? AND status='ACTIVE' AND group_id>? ORDER BY group_id LIMIT ?",
                (row,index)->uuid(row.getBytes(1)),bytes(organization),bytes(target),
                bytes(request.after()==null?new UUID(0,0):request.after()),request.limit());
        Relationship member=members.getFirst();
        return new Inspection("relationships",List.of(),new Relationship(member.membershipId(),member.organizationRole(),List.copyOf(groups)),
                null,null,null,false,false);
    }
    private Inspection projection(Request request) {
        UUID organization=required(request.organizationId());activeOrganization(organization);
        List<Projection> states=jdbc.query("SELECT required_revision,applied_revision,required_source_version,applied_source_version,sync_status,last_error_code FROM spicedb_organization_sync_state WHERE organization_id=?",
                (row,index)->new Projection(row.getLong(1),row.getLong(2),row.getLong(3),row.getLong(4),row.getString(5),row.getString(6)),bytes(organization));
        if(states.size()!=1)throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"PROJECTION_STATE_UNAVAILABLE");
        return new Inspection("projection",List.of(),null,states.getFirst(),null,"organization_v2",canaryEnabled,
                canaryEnabled && canaryOrganizations.contains(organization));
    }
    private Inspection explanation(Request request) {
        UUID organization=required(request.organizationId());UUID target=required(request.targetAccountId());
        UUID operation=required(request.operationId());activeOrganization(organization);
        List<String[]> operations=jdbc.query("SELECT service_id,operation_key FROM iam_operation WHERE id=? AND status='ACTIVE'",
                (row,index)->new String[]{row.getString(1),row.getString(2)},bytes(operation));
        if(operations.size()!=1)throw denied();String[] selected=operations.getFirst();
        if(!Set.of("auth-service","document-service").contains(selected[0]))throw denied();
        boolean allowed=authorization.previewTarget(organization,target,null,selected[0],selected[1]);
        Long version=jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?",Long.class,bytes(organization));
        if(version==null)throw denied();
        return new Inspection("explanation",List.of(),null,null,
                new Explanation(allowed?"ALLOWED":"DENIED",allowed?"CURRENT_POLICY_ALLOWS":"CURRENT_POLICY_DENIES",version),
                null,false,false);
    }
    private void activeOrganization(UUID organization) {
        Integer active=jdbc.queryForObject("SELECT COUNT(*) FROM organization WHERE id=? AND status='ACTIVE' AND type IN('COMPANY','CUSTOM')",Integer.class,bytes(organization));
        if(active==null || active!=1)throw denied();
    }
    private static UUID required(UUID value) { if(value==null)throw bad();return value; }
    private static UUID uuid(byte[] value) { ByteBuffer buffer=ByteBuffer.wrap(value);return new UUID(buffer.getLong(),buffer.getLong()); }
    private static UUID optional(byte[] value) { return value==null?null:uuid(value); }
    private static ResponseStatusException bad() { return new ResponseStatusException(HttpStatus.BAD_REQUEST,"INVALID_OPERATOR_INSPECTION"); }
    private static ResponseStatusException denied() { return new ResponseStatusException(HttpStatus.FORBIDDEN,"OPERATOR_INSPECTION_DENIED"); }
}
