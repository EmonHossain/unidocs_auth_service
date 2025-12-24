package com.unidocs.auth.authorization.controlplane;

import java.sql.Timestamp;
import java.util.*;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Service
public class DeveloperCatalogService {
    public record Proof(UUID accountId,String password,String secondFactor,String reason) {
        public Proof(UUID accountId,String password,String secondFactor) { this(accountId,password,secondFactor,null); }
        @Override public String toString(){return "Proof[REDACTED]";}
    }
    public record Item(UUID id,String key,String status,long version,List<UUID> authorities,
            String serviceId,String matchMode,Boolean requiresScopedAuthorities,UUID roleId,UUID operationId) { }
    public record Page(List<Item> items,UUID nextCursor) { }
    public record Result(UUID id,long version) { }
    private final JdbcTemplate jdbc;
    private final DeveloperGate gate;
    private final DeveloperOperatorGate operatorGate;
    private final boolean operatorMode;
    private final OutboxRepository outbox;
    public DeveloperCatalogService(JdbcTemplate jdbc,DeveloperGate gate,OutboxRepository outbox){this(jdbc,gate,outbox,(DeveloperOperatorGate)null,false);}
    @org.springframework.beans.factory.annotation.Autowired
    public DeveloperCatalogService(JdbcTemplate jdbc,DeveloperGate gate,OutboxRepository outbox,
            org.springframework.beans.factory.ObjectProvider<DeveloperOperatorGate> operatorGates,
            @org.springframework.beans.factory.annotation.Value("${auth.developer.operator.enabled:false}") boolean operatorMode){
        this(jdbc,gate,outbox,operatorGates.getIfAvailable(),operatorMode);
    }
    private DeveloperCatalogService(JdbcTemplate jdbc,DeveloperGate gate,OutboxRepository outbox,
            DeveloperOperatorGate operatorGate,boolean operatorMode){
        this.jdbc=jdbc;this.gate=gate;this.outbox=outbox;this.operatorGate=operatorGate;this.operatorMode=operatorMode;
    }
    private record Actor(UUID principalId,UUID sessionId,java.time.Instant now,SessionAccess.Context legacy) { }
    private <T> T admitted(Jwt jwt,Proof proof,String key,java.util.function.Function<Actor,T> command) {
        if(operatorMode) {
            if(proof.accountId()!=null)throw bad();
            if(operatorGate==null)throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"OPERATOR_GATE_UNAVAILABLE");
            return operatorGate.execute(jwt,proof.password(),proof.secondFactor(),key,
                    context->command.apply(new Actor(context.operatorId(),context.sessionId(),context.now(),null)));
        }
        return gate.execute(jwt,proof.accountId(),proof.password(),proof.secondFactor(),key,
                context->command.apply(new Actor(proof.accountId(),context.session().id(),context.now(),context)));
    }

    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public Page catalog(Jwt jwt,Proof proof,String kind,UUID after,int limit){
        if(proof==null || kind==null || limit<1 || limit>100) throw bad();
        String table=switch(kind){case "roles"->"iam_role";case "authorities"->"iam_authority";case "operations"->"iam_operation";
            case "categories"->"iam_stakeholder_role_binding";case "baselines"->"iam_context_member_role_binding";
            case "relationships"->"iam_group_relationship_role_binding";case "student-responsibilities"->"iam_student_role_binding";case "policies"->"iam_operation_policy";default->throw bad();};
        return admitted(jwt,proof,null,context->{
            if(Set.of("categories","baselines","relationships","student-responsibilities").contains(kind)) {
                String column="relationships".equals(kind)?"relationship_key":"student-responsibilities".equals(kind)?"responsibility":"category_key";
                List<Item> items=jdbc.query("SELECT * FROM "+table+" ORDER BY "+column,(rs,n)->
                    new Item(id(rs,"role_id"),rs.getString(column),rs.getString("status"),rs.getLong("version"),List.of(),null,null,null,id(rs,"role_id"),null));
                return new Page(items,null);
            }
            List<Item> items=jdbc.query("SELECT * FROM "+table+(after==null?"":" WHERE id>?")+" ORDER BY id LIMIT ?",(rs,n)->{
                UUID identity=id(rs,"id");
                return new Item(identity,rs.getString(switch(kind){case "roles"->"role_key";case "authorities"->"authority_key";case "operations"->"operation_key";default->"match_mode";}),
                    rs.getString("status"),rs.getLong("version"),List.of(),"roles".equals(kind)?null:rs.getString("service_id"),
                    "policies".equals(kind)?rs.getString("match_mode"):null,"policies".equals(kind)?rs.getBoolean("requires_scoped_authorities"):null,null,"policies".equals(kind)?id(rs,"operation_id"):null);
            },after==null?new Object[]{limit+1}:new Object[]{bytes(after),limit+1});
            boolean more=items.size()>limit;
            List<Item> page=List.copyOf(items.subList(0,Math.min(items.size(),limit)));
            if(!page.isEmpty() && Set.of("roles","policies").contains(kind)) {
                String mapping="roles".equals(kind)?"iam_role_authority":"iam_policy_authority";
                String owner="roles".equals(kind)?"role_id":"policy_id";
                Map<UUID,List<UUID>> byOwner=new HashMap<>();
                String placeholders=String.join(",",Collections.nCopies(page.size(),"?"));
                jdbc.query("SELECT "+owner+",authority_id FROM "+mapping+" WHERE "+owner+" IN ("+placeholders+") ORDER BY "+owner+",authority_id LIMIT 6401",rs->{
                    byOwner.computeIfAbsent(id(rs,owner),ignored->new ArrayList<>()).add(id(rs,"authority_id"));
                },page.stream().map(item->bytes(item.id())).toArray());
                page=page.stream().map(item->new Item(item.id(),item.key(),item.status(),item.version(),List.copyOf(byOwner.getOrDefault(item.id(),List.of())),item.serviceId(),item.matchMode(),item.requiresScopedAuthorities(),item.roleId(),item.operationId())).toList();
            }
            return new Page(page,more?page.getLast().id():null);
        });
    }

    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public Result role(Jwt jwt,Proof proof,UUID role,String key,String status,List<UUID> authorities,String match,String requestKey){
        if(proof==null)throw bad();
        validateStatus(status); validateAuthorities(authorities,false);
        if(key==null || !key.matches("[A-Za-z][A-Za-z0-9]*(?:[._-][A-Za-z0-9]+)*") || key.length()>128) throw bad();
        return mutate(jwt,proof,"ROLE",role,match,requestKey,key+"|"+status+"|"+sorted(authorities),context->{
            UUID identity=role==null?UUID.randomUUID():role;
            long current=version("iam_role",identity);
            expected(match,current);
            validateActiveAuthorities(authorities,null);
            Timestamp now=Timestamp.from(context.now());
            if(current==0) jdbc.update("INSERT INTO iam_role(id,role_key,status,version,created_at,updated_at) VALUES(?,?,?,1,?,?)",bytes(identity),key,status,now,now);
            else jdbc.update("UPDATE iam_role SET role_key=?,status=?,version=version+1,updated_at=? WHERE id=?",key,status,now,bytes(identity));
            jdbc.update("DELETE FROM iam_role_authority WHERE role_id=?",bytes(identity));
            for(UUID authority:authorities)jdbc.update("INSERT INTO iam_role_authority(role_id,authority_id) VALUES(?,?)",bytes(identity),bytes(authority));
            return new Result(identity,current+1);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public Result binding(Jwt jwt,Proof proof,String kind,String binding,UUID role,String status,String match,String requestKey){
        if(proof==null || binding==null)throw bad();
        String table;String column;
        if("baselines".equals(kind) && Set.of("INDIVIDUAL","ORGANIZATION","STUDENT").contains(binding)) {table="iam_context_member_role_binding";column="category_key";}
        else if("relationships".equals(kind) && Set.of("OWNER","MEMBER").contains(binding)){table="iam_group_relationship_role_binding";column="relationship_key";}
        else if("student-responsibilities".equals(kind) && Set.of("STUDENT","STUDENT_ADMIN","STUDY_OWNER","STUDY_MEMBER").contains(binding)){table="iam_student_role_binding";column="responsibility";}
        else throw bad();
        if(role==null)throw bad();validateStatus(status);
        return mutate(jwt,proof,"BINDING",role,match,requestKey,kind+"|"+binding+"|"+role+"|"+status,context->{
            if(jdbc.queryForList("SELECT id FROM iam_role WHERE id=? AND status='ACTIVE'",bytes(role)).isEmpty())throw bad();
            List<Long> versions=jdbc.query("SELECT version FROM "+table+" WHERE "+column+"=? FOR UPDATE",(rs,n)->rs.getLong(1),binding);
            long current=versions.isEmpty()?0:versions.getFirst();expected(match,current);
            jdbc.update("INSERT INTO "+table+"("+column+",role_id,status,version) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE role_id=VALUES(role_id),status=VALUES(status),version=VALUES(version)",binding,bytes(role),status,current+1);
            return new Result(role,current+1);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public Result category(Jwt jwt,Proof proof,String category,UUID role,String status,String match,String requestKey){
        if(proof==null || category==null || !Set.of("INDIVIDUAL","ORGANIZATION","STUDENT").contains(category) || role==null) throw bad();
        validateStatus(status);
        return mutate(jwt,proof,"CATEGORY",role,match,requestKey,category+"|"+role+"|"+status,context->{
            if(jdbc.queryForList("SELECT id FROM iam_role WHERE id=? AND status='ACTIVE'",bytes(role)).isEmpty())throw bad();
            List<Long> versions=jdbc.query("SELECT version FROM iam_stakeholder_role_binding WHERE category_key=? FOR UPDATE",(rs,n)->rs.getLong(1),category);
            long current=versions.isEmpty()?0:versions.getFirst();expected(match,current);
            Timestamp now=Timestamp.from(context.now());
            jdbc.update("INSERT INTO iam_stakeholder_role_binding(category_key,role_id,status,version,created_at,updated_at) VALUES(?,?,?,?,?,?) ON DUPLICATE KEY UPDATE role_id=VALUES(role_id),status=VALUES(status),version=VALUES(version),updated_at=VALUES(updated_at)",category,bytes(role),status,current+1,now,now);
            return new Result(role,current+1);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public Result policy(Jwt jwt,Proof proof,UUID operation,String mode,boolean scoped,String status,List<UUID> authorities,String match,String requestKey){
        if(proof==null || operation==null)throw bad();
        validateStatus(status);validateAuthorities(authorities,true);
        if(mode==null || !Set.of("ALL_OF","ANY_OF").contains(mode))throw bad();
        return mutate(jwt,proof,"POLICY",operation,match,requestKey,mode+"|"+scoped+"|"+status+"|"+sorted(authorities),context->{
            List<String> services=jdbc.query("SELECT service_id FROM iam_operation WHERE id=? AND status='ACTIVE' FOR UPDATE",(rs,n)->rs.getString(1),bytes(operation));
            if(services.size()!=1)throw bad();String service=services.getFirst();validateActiveAuthorities(authorities,service);
            List<Result> existing=jdbc.query("SELECT id,version FROM iam_operation_policy WHERE operation_id=? FOR UPDATE",(rs,n)->new Result(id(rs,"id"),rs.getLong("version")),bytes(operation));
            Result previous=existing.isEmpty()?new Result(UUID.randomUUID(),0):existing.getFirst();expected(match,previous.version());
            Timestamp now=Timestamp.from(context.now());
            if(previous.version()==0)jdbc.update("INSERT INTO iam_operation_policy(id,operation_id,service_id,match_mode,requires_scoped_authorities,status,version,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)",bytes(previous.id()),bytes(operation),service,mode,scoped,status,now,now);
            else jdbc.update("UPDATE iam_operation_policy SET match_mode=?,requires_scoped_authorities=?,status=?,version=version+1,updated_at=? WHERE id=?",mode,scoped,status,now,bytes(previous.id()));
            jdbc.update("DELETE FROM iam_policy_authority WHERE policy_id=?",bytes(previous.id()));int slot=1;
            for(UUID authority:authorities)jdbc.update("INSERT INTO iam_policy_authority(policy_id,service_id,authority_id,authority_slot) VALUES(?,?,?,?)",bytes(previous.id()),service,bytes(authority),slot++);
            return new Result(previous.id(),previous.version()+1);
        });
    }
    private Result mutate(Jwt jwt,Proof proof,String action,UUID target,String match,String key,String payload,java.util.function.Function<Actor,Result> command){
        if(operatorMode && (proof.reason()==null || proof.reason().isBlank() || proof.reason().length()>512))throw bad();
        if(match==null)throw new ResponseStatusException(HttpStatus.PRECONDITION_REQUIRED);
        if(key==null || !key.matches("[A-Za-z0-9._-]{1,128}"))throw bad();
        String hash=DeveloperGate.hash(action+"|"+target+"|"+match+"|"+payload+(operatorMode?"|"+proof.reason().strip():""));
        return admitted(jwt,proof,key,context->{
            jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR UPDATE",Long.class);
            if(!operatorMode) {gate.checkCurrent(jwt,context.legacy(),proof.accountId());gate.checkFactor(proof.accountId(),proof.secondFactor());}
            String requestTable=operatorMode?"iam_developer_operator_request":"iam_controlplane_request";
            String principalColumn=operatorMode?"operator_id":"account_id";
            List<Map<String,Object>> prior=jdbc.queryForList("SELECT request_hash,result_id,result_version FROM "+requestTable+" WHERE "+principalColumn+"=? AND idempotency_key=?",bytes(context.principalId()),key);
            if(!prior.isEmpty()){
                Map<String,Object> row=prior.getFirst();if(!hash.equals(row.get("request_hash")))throw new ResponseStatusException(HttpStatus.CONFLICT);
                return new Result(uuid((byte[])row.get("result_id")),((Number)row.get("result_version")).longValue());
            }
            Result result=command.apply(context);
            jdbc.update("UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL'");
            if(operatorMode)operatorGate.audit(new DeveloperOperatorGate.Context(context.principalId(),context.sessionId(),context.now()),
                    "CATALOG_"+action+"_CHANGED",result.id(),result.version(),proof.reason().strip());
            else gate.audit(context.legacy(),proof.accountId(),"CATALOG_"+action+"_CHANGED",result.id(),result.version());
            long global=jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL'",Long.class);
            outbox.lifecycle("IAM_POLICY",result.id(),global,"IAM_POLICY_CHANGED",operatorMode?null:proof.accountId(),null,null,context.now());
            jdbc.update("INSERT INTO "+requestTable+"("+principalColumn+",idempotency_key,request_hash,result_id,result_version,created_at) VALUES(?,?,?,?,?,?)",bytes(context.principalId()),key,hash,bytes(result.id()),result.version(),Timestamp.from(context.now()));
            return result;
        });
    }
    private long version(String table,UUID identity){List<Long> rows=jdbc.query("SELECT version FROM "+table+" WHERE id=? FOR UPDATE",(rs,n)->rs.getLong(1),bytes(identity));return rows.isEmpty()?0:rows.getFirst();}
    static void expected(String match,long version){if(match==null)throw new ResponseStatusException(HttpStatus.PRECONDITION_REQUIRED);if(!("\""+version+"\"").equals(match))throw new ResponseStatusException(HttpStatus.PRECONDITION_FAILED);}
    static void validateAuthorities(List<UUID> values,boolean nonempty){if(values==null || values.size()>64 || nonempty&&values.isEmpty() || values.stream().anyMatch(Objects::isNull) || new HashSet<>(values).size()!=values.size())throw bad();}
    private void validateActiveAuthorities(List<UUID> authorities,String service){for(UUID authority:authorities)if(jdbc.queryForList("SELECT id FROM iam_authority WHERE id=? AND status='ACTIVE'"+(service==null?"":" AND service_id=?"),service==null?new Object[]{bytes(authority)}:new Object[]{bytes(authority),service}).isEmpty())throw bad();}
    private static String sorted(List<UUID> values){return values.stream().map(UUID::toString).sorted().toList().toString();}
    private static UUID uuid(byte[] bytes){java.nio.ByteBuffer buffer=java.nio.ByteBuffer.wrap(bytes);return new UUID(buffer.getLong(),buffer.getLong());}
    private static UUID id(java.sql.ResultSet rows,String column)throws java.sql.SQLException{return uuid(rows.getBytes(column));}
    private static void validateStatus(String status){if(status==null || !Set.of("ACTIVE","DISABLED").contains(status))throw bad();}
    private static ResponseStatusException bad(){return new ResponseStatusException(HttpStatus.BAD_REQUEST,"INVALID_CATALOG_COMMAND");}
}
