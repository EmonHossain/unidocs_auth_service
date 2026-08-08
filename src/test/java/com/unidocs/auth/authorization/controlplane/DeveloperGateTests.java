package com.unidocs.auth.authorization.controlplane;

import java.time.*;
import java.sql.Timestamp;
import java.util.*;
import java.util.function.Function;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.persistence.SessionRepository;
import com.unidocs.auth.session.domain.*;
import com.unidocs.auth.credential.application.PasswordAndPinVerifier;
import com.unidocs.auth.account.domain.AccountChallenge.Method;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class DeveloperGateTests {
    private final SessionAccess access=mock(SessionAccess.class);
    private final SessionRepository sessions=mock(SessionRepository.class);
    private final JdbcTemplate jdbc=mock(JdbcTemplate.class);
    private final PasswordAndPinVerifier passwords=mock(PasswordAndPinVerifier.class);
    private final DeveloperGate gate=new DeveloperGate(access,sessions,jdbc,passwords,Clock.fixed(Instant.parse("2026-10-14T12:00:00Z"),ZoneOffset.UTC));
    private final UUID account=UUID.randomUUID(),session=UUID.randomUUID(),user=UUID.randomUUID(),group=UUID.randomUUID();
    private final Instant now=Instant.parse("2026-10-14T12:00:00Z");
    private final String factor="a".repeat(64);
    private SessionAccess.Context context;
    private Jwt jwt;
    @BeforeEach void setup(){
        SessionAccountGrant grant=new SessionAccountGrant(session,account,"ACTIVE","LOGIN",1,now.plusSeconds(600),now.plusSeconds(600));
        context=new SessionAccess.Context(new UserSession(session,group,account,"ACTIVE",now,now,now.plusSeconds(600),null),new SessionRepository.Owner(user,"Actor",account),grant,now);
        jwt=Jwt.withTokenValue("token").header("alg","RS256").subject(account.toString()).claim("sid",session.toString()).expiresAt(now.plusSeconds(600)).build();
        when(access.execute(any(),any(),any())).thenAnswer(invocation->{Function<SessionAccess.Context,Object> work=invocation.getArgument(2);return work.apply(context);});
        when(sessions.sessionGroup(session)).thenReturn(Optional.of(group));
        when(sessions.owner(group)).thenReturn(Optional.of(context.owner()));
        when(sessions.liveGrant(any(),eq(account),any())).thenReturn(Optional.of(grant));
        when(sessions.accountIdentity(account)).thenReturn(Optional.of(new SessionRepository.Identity(UUID.randomUUID(),account,user,group,account,"Actor","hash",1,true)));
        when(jdbc.queryForList(startsWith("SELECT status"),any(Object[].class))).thenReturn(List.of(new HashMap<>(Map.of("status","ACTIVE","failed_attempts",0))));
        when(jdbc.queryForList(startsWith("SELECT consumed_key"),any(Object[].class))).thenReturn(List.of(new HashMap<>()));
        when(passwords.verify(Method.PASSWORD,"password","hash")).thenReturn(true);
        when(jdbc.queryForObject(startsWith("SELECT COUNT(*) FROM iam_developer_factor"),eq(Integer.class),any(Object[].class))).thenReturn(1);
    }
    @Test void permitsCurrentIndependentEligibilityAndBothProofs(){assertThat(gate.<String>execute(jwt,account,"password",factor,"retry",c->"ok")).isEqualTo("ok");}
    @Test void reconciliationDelegatesAdditionalAccountGroupsToTheOrderedSessionFence() {
        UUID other=UUID.randomUUID();
        when(access.executeForGroups(any(),any(),eq(List.of(other)),any())).thenAnswer(invocation->{Function<SessionAccess.Context,Object> work=invocation.getArgument(3);return work.apply(context);});
        assertThat(gate.<String>executeForGroups(jwt,account,"password",factor,"reconciliation",List.of(other),c->"reconciled")).isEqualTo("reconciled");
        verify(access).executeForGroups(eq(session),eq(account),eq(List.of(other)),any());
    }
    @Test void missingEligibilityCannotBeReplacedByRoleOrLinkedGrant(){
        when(jdbc.queryForList(startsWith("SELECT status"),any(Object[].class))).thenReturn(List.of());
        assertThatThrownBy(()->gate.execute(jwt,account,"password",factor,null,c->"bad")).isInstanceOf(ResponseStatusException.class);
        verify(jdbc,never()).update(startsWith("UPDATE iam_developer_factor"),any(Object[].class));
    }
    @Test void failedPasswordIsRecordedWithoutInvokingMutation(){
        when(passwords.verify(any(),any(),any())).thenReturn(false);
        assertThatThrownBy(()->gate.execute(jwt,account,"password",factor,"retry",c->{throw new AssertionError();})).isInstanceOf(ResponseStatusException.class);
        verify(jdbc).update(startsWith("UPDATE iam_developer_eligibility SET failed_attempts=?"),any(Object[].class));
        verify(jdbc,never()).update(startsWith("UPDATE iam_developer_factor"),any(Object[].class));
    }
    @Test void independentFactorReplayFailsForAnotherOperation(){
        when(jdbc.queryForList(startsWith("SELECT consumed_key"),any(Object[].class))).thenReturn(List.of(Map.of("consumed_key","old-key","consumed_at",Timestamp.from(now))));
        assertThatThrownBy(()->gate.execute(jwt,account,"password",factor,"new-key",c->{throw new AssertionError();})).isInstanceOf(ResponseStatusException.class);
    }
    @Test void sameIdempotencyScopeAllowsOnlySuccessfulRetryPath(){
        when(jdbc.queryForList(startsWith("SELECT consumed_key"),any(Object[].class))).thenReturn(List.of(Map.of("consumed_key","retry","consumed_at",Timestamp.from(now))));
        assertThat(gate.<String>execute(jwt,account,"password",factor,"retry",c->"cached-result")).isEqualTo("cached-result");
    }
    @Test void oldAuthenticationFailsBeforePasswordComparison(){
        context=new SessionAccess.Context(new UserSession(session,group,account,"ACTIVE",now.minusSeconds(901),now,now.plusSeconds(600),null),context.owner(),context.grant(),now);
        assertThatThrownBy(()->gate.execute(jwt,account,"password",factor,null,c->"bad")).isInstanceOf(ResponseStatusException.class);
        verify(jdbc,never()).update(startsWith("UPDATE iam_developer_factor"),any(Object[].class));
    }
    @Test void attemptLockoutCannotBeResetByAnotherSession(){
        when(jdbc.queryForList(startsWith("SELECT status"),any(Object[].class))).thenReturn(List.of(Map.of("status","ACTIVE","failed_attempts",5,"proof_window_at",Timestamp.from(now.minusSeconds(1)))));
        assertThatThrownBy(()->gate.execute(jwt,account,"password",factor,null,c->"bad")).isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(429));
        verify(jdbc,never()).update(startsWith("UPDATE iam_developer_factor"),any(Object[].class));
    }
    @Test void credentialChangeBetweenPasswordCheckAndFencedCommandFailsClosed(){
        UUID identity=UUID.randomUUID();
        SessionRepository.Identity before=new SessionRepository.Identity(identity,account,user,group,account,"Actor","hash",1,true);
        SessionRepository.Identity changed=new SessionRepository.Identity(identity,account,user,group,account,"Actor","new-hash",2,true);
        when(sessions.accountIdentity(account)).thenReturn(Optional.of(before),Optional.of(changed));
        assertThatThrownBy(()->gate.execute(jwt,account,"password",factor,"retry",c->{throw new AssertionError();})).isInstanceOf(ResponseStatusException.class);
    }
    @Test void factorExpiringDuringLocksCannotAuthorizeCommand(){
        when(jdbc.queryForObject(startsWith("SELECT COUNT(*) FROM iam_developer_factor"),eq(Integer.class),any(Object[].class))).thenReturn(0);
        assertThatThrownBy(()->gate.execute(jwt,account,"password",factor,"retry",c->{throw new AssertionError();})).isInstanceOf(ResponseStatusException.class);
    }
}
