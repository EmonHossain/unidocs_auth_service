package com.unidocs.auth.authorization.controlplane;

import java.time.*;
import java.sql.Timestamp;
import java.util.*;
import java.util.function.Function;
import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.*;
import com.unidocs.auth.session.persistence.SessionRepository;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SpringBootTest
@Transactional
class DeveloperCatalogIntegrationTests extends MySqlIntegrationTest {
    @Autowired DeveloperCatalogService service;
    @Autowired JdbcTemplate jdbc;
    @Autowired PasswordEncoder passwords;
    @MockitoBean SessionAccess access;
    @MockitoBean SessionRepository sessions;
    private UUID account,user,group,session,authority,operation;
    private Jwt jwt;
    private Instant now;
    private String factor;
    private DeveloperCatalogService.Proof proof;
    @BeforeEach void fixture(){
        account=UUID.randomUUID();user=UUID.randomUUID();group=UUID.randomUUID();session=UUID.randomUUID();authority=UUID.randomUUID();operation=UUID.randomUUID();
        now=Instant.now();Timestamp timestamp=Timestamp.from(now);
        jdbc.update("INSERT INTO users(id,display_name,status,created_at,updated_at) VALUES(?,'Developer','ACTIVE',?,?)",bytes(user),timestamp,timestamp);
        jdbc.update("INSERT INTO user_account(id,user_id,type,display_name,status,created_at,updated_at) VALUES(?,?,'PERSONAL','Developer','ACTIVE',?,?)",bytes(account),bytes(user),timestamp,timestamp);
        jdbc.update("INSERT INTO iam_developer_eligibility(account_id,status,version,provisioned_by,reason,updated_at) VALUES(?,'ACTIVE',1,'integration','fixture',?)",bytes(account),timestamp);
        factor="a".repeat(64);
        jdbc.update("INSERT INTO iam_developer_factor(secret_hash,account_id,expires_at) VALUES(?,?,?)",DeveloperGate.hash(factor),bytes(account),Timestamp.from(now.plusSeconds(3600)));
        jdbc.update("INSERT INTO iam_authority(id,service_id,authority_key,status,version,created_at,updated_at) VALUES(?,'test-service',?,'ACTIVE',1,?,?)",bytes(authority),"test."+UUID.randomUUID().toString(),timestamp,timestamp);
        jdbc.update("INSERT INTO iam_operation(id,service_id,operation_key,status,version,created_at,updated_at) VALUES(?,'test-service',?,'ACTIVE',1,?,?)",bytes(operation),"test."+UUID.randomUUID().toString(),timestamp,timestamp);
        SessionAccountGrant grant=new SessionAccountGrant(session,account,"ACTIVE","LOGIN",1,now.plusSeconds(600),now.plusSeconds(600));
        SessionAccess.Context context=new SessionAccess.Context(new UserSession(session,group,account,"ACTIVE",now,now,now.plusSeconds(600),null),new SessionRepository.Owner(user,"Developer",account),grant,now);
        when(access.execute(any(),any(),any())).thenAnswer(invocation->{Function<SessionAccess.Context,Object> work=invocation.getArgument(2);return work.apply(context);});
        when(sessions.sessionGroup(session)).thenReturn(Optional.of(group));
        when(sessions.owner(group)).thenReturn(Optional.of(context.owner()));
        when(sessions.liveGrant(any(),eq(account),any())).thenReturn(Optional.of(grant));
        when(sessions.accountIdentity(account)).thenReturn(Optional.of(new SessionRepository.Identity(UUID.randomUUID(),account,user,group,account,"Developer",passwords.encode("test-password"),1,true)));
        jwt=Jwt.withTokenValue("token").header("alg","RS256").subject(account.toString()).claim("sid",session.toString()).expiresAt(now.plusSeconds(600)).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt,List.of()));
        proof=new DeveloperCatalogService.Proof(account,"test-password",factor);
    }
    @AfterEach void clearSecurity(){SecurityContextHolder.clearContext();}
    @Test void roleMutationCommitsRevisionAuditOutboxAndIdempotentResult(){
        long revision=jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL'",Long.class);
        String key="role."+UUID.randomUUID().toString().replace("-","");
        DeveloperCatalogService.Result first=service.role(jwt,proof,null,key,"ACTIVE",List.of(authority),"\"0\"","create-role");
        DeveloperCatalogService.Result repeated=service.role(jwt,proof,null,key,"ACTIVE",List.of(authority),"\"0\"","create-role");
        assertThat(repeated).isEqualTo(first);
        assertThat(jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL'",Long.class)).isEqualTo(revision+1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_controlplane_audit WHERE aggregate_id=? AND action_key='CATALOG_ROLE_CHANGED'",Integer.class,bytes(first.id()))).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE aggregate_id=? AND event_type='IAM_POLICY_CHANGED'",Integer.class,bytes(first.id()))).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_role_authority WHERE role_id=?",Integer.class,bytes(first.id()))).isEqualTo(1);
        assertThatThrownBy(()->service.role(jwt,proof,null,key,"DISABLED",List.of(),"\"0\"","create-role")).isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(409));
    }
    @Test void categoryAndOperationPolicyRejectStaleAndCrossServiceRequirements(){
        UUID role=UUID.randomUUID();Timestamp timestamp=Timestamp.from(now);
        jdbc.update("INSERT INTO iam_role(id,role_key,status,version,created_at,updated_at) VALUES(?,?,'ACTIVE',1,?,?)",bytes(role),"test."+role.toString().replace("-",""),timestamp,timestamp);
        assertThatThrownBy(()->service.category(jwt,proof,"INDIVIDUAL",role,"ACTIVE","\"99999\"","category-stale")).isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(412));
        issueFactor("b".repeat(64));
        DeveloperCatalogService.Result result=service.policy(jwt,proof,operation,"ALL_OF",false,"ACTIVE",List.of(authority),"\"0\"","policy-create");
        assertThat(result.version()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_policy_authority WHERE policy_id=?",Integer.class,bytes(result.id()))).isEqualTo(1);
        UUID foreign=UUID.randomUUID();
        jdbc.update("INSERT INTO iam_authority(id,service_id,authority_key,status,version,created_at,updated_at) VALUES(?,'foreign-service','file.share','ACTIVE',1,?,?)",bytes(foreign),timestamp,timestamp);
        issueFactor("c".repeat(64));
        assertThatThrownBy(()->service.policy(jwt,proof,operation,"ALL_OF",false,"ACTIVE",List.of(foreign),"\"1\"","policy-invalid")).isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(400));
    }
    @Test void missingIndependentEligibilityDeniesEvenWithLiveGrant(){
        jdbc.update("UPDATE iam_developer_eligibility SET status='REVOKED' WHERE account_id=?",bytes(account));
        assertThatThrownBy(()->service.catalog(jwt,proof,"roles",null,10)).isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(403));
    }
    @Test void baselineAndRelationshipBindingsHaveIndependentVersionAndAudit(){
        UUID role=UUID.randomUUID();Timestamp timestamp=Timestamp.from(now);
        jdbc.update("INSERT INTO iam_role(id,role_key,status,version,created_at,updated_at) VALUES(?,?,'ACTIVE',1,?,?)",bytes(role),"TEST_BASELINE_"+role.toString().replace("-",""),timestamp,timestamp);
        long baseline=jdbc.queryForObject("SELECT version FROM iam_context_member_role_binding WHERE category_key='INDIVIDUAL'",Long.class);
        DeveloperCatalogService.Result result=service.binding(jwt,proof,"baselines","INDIVIDUAL",role,"ACTIVE","\""+baseline+"\"","baseline-change");
        assertThat(result.version()).isEqualTo(baseline+1);
        assertThat(jdbc.queryForObject("SELECT BIN_TO_UUID(role_id) FROM iam_context_member_role_binding WHERE category_key='INDIVIDUAL'",String.class)).isEqualTo(role.toString());
        issueFactor("b".repeat(64));
        long relationship=jdbc.queryForObject("SELECT version FROM iam_group_relationship_role_binding WHERE relationship_key='MEMBER'",Long.class);
        service.binding(jwt,proof,"relationships","MEMBER",role,"ACTIVE","\""+relationship+"\"","member-change");
        assertThat(jdbc.queryForObject("SELECT version FROM iam_group_relationship_role_binding WHERE relationship_key='MEMBER'",Long.class)).isEqualTo(relationship+1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_controlplane_audit WHERE action_key='CATALOG_BINDING_CHANGED' AND aggregate_id=?",Integer.class,bytes(role))).isEqualTo(2);
    }
    private void issueFactor(String secret){jdbc.update("INSERT INTO iam_developer_factor(secret_hash,account_id,expires_at) VALUES(?,?,?)",DeveloperGate.hash(secret),bytes(account),Timestamp.from(now.plusSeconds(3600)));proof=new DeveloperCatalogService.Proof(account,"test-password",secret);}
}
