package com.unidocs.auth.authorization.controlplane;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

class DeveloperOperatorGateTests {
    private final JdbcTemplate jdbc=mock(JdbcTemplate.class);
    private final PasswordEncoder passwords=mock(PasswordEncoder.class);
    private final PlatformTransactionManager transactions=mock(PlatformTransactionManager.class);
    private final Clock clock=Clock.fixed(Instant.parse("2026-10-18T12:00:00Z"), ZoneOffset.UTC);
    private final DeveloperOperatorGate gate=new DeveloperOperatorGate(jdbc,passwords,clock,transactions);

    @Test void malformedFactorNeverReachesOperatorDatabaseOrCommand() {
        Jwt jwt=token("DEVELOPER_OPERATOR");
        Function<DeveloperOperatorGate.Context,String> command=mock(Function.class);
        assertThatThrownBy(()->gate.execute(jwt,"synthetic-password","not-a-factor",null,command))
                .isInstanceOf(org.springframework.web.server.ResponseStatusException.class);
        verifyNoInteractions(jdbc,passwords,transactions,command);
    }

    @Test void productRealmTokenCannotExecuteOperatorCommand() {
        when(transactions.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        when(jdbc.query(anyString(),any(org.springframework.jdbc.core.RowMapper.class),any(Object[].class)))
                .thenReturn(List.of());
        Function<DeveloperOperatorGate.Context,String> command=mock(Function.class);
        assertThatThrownBy(()->gate.execute(token("PRODUCT"),"synthetic-password","a".repeat(64),null,command))
                .isInstanceOf(AuthenticationFailure.class);
        verifyNoInteractions(command);
        verify(jdbc,never()).update(anyString(),any(Object[].class));
    }

    @Test void expiredProofLockoutStartsANewWindowOnFailure() throws Exception {
        UUID operator=UUID.randomUUID();UUID session=UUID.randomUUID();Instant now=clock.instant();
        when(transactions.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        when(passwords.matches(anyString(),eq("hash"))).thenReturn(false);
        when(jdbc.query(anyString(),any(RowMapper.class),any(Object[].class))).thenAnswer(invocation->{
            String sql=invocation.getArgument(0);RowMapper<?> mapper=invocation.getArgument(1);
            ResultSet row=mock(ResultSet.class);
            if(sql.contains("FROM iam_developer_session s")) {
                when(row.getTimestamp(1)).thenReturn(Timestamp.from(now.minusSeconds(60)));
                when(row.getTimestamp(2)).thenReturn(Timestamp.from(now.plusSeconds(60)));
                when(row.getLong(3)).thenReturn(1L);when(row.getLong(4)).thenReturn(1L);
                when(row.getString(5)).thenReturn("ACTIVE");when(row.getBoolean(6)).thenReturn(true);
            } else if(sql.startsWith("SELECT id,password_hash")) {
                when(row.getBytes(1)).thenReturn(bytes(operator));when(row.getString(2)).thenReturn("hash");
                when(row.getLong(3)).thenReturn(1L);
            } else if(sql.startsWith("SELECT password_hash,credential_version")) {
                when(row.getString(1)).thenReturn("hash");when(row.getLong(2)).thenReturn(1L);
                when(row.getInt(3)).thenReturn(5);
                when(row.getTimestamp(4)).thenReturn(Timestamp.from(now.minus(Duration.ofMinutes(16))));
            } else return List.of();
            return List.of(mapper.mapRow(row,0));
        });
        Jwt jwt=Jwt.withTokenValue("synthetic-token").header("alg","RS256")
                .subject(operator.toString()).claim("sid",session.toString())
                .claim("realm","DEVELOPER_OPERATOR").issuedAt(now.minusSeconds(60))
                .expiresAt(now.plusSeconds(60)).build();
        assertThatThrownBy(()->gate.execute(jwt,"wrong-password","a".repeat(64),null,ignored->"denied"))
                .isInstanceOf(org.springframework.web.server.ResponseStatusException.class);
        verify(jdbc).update(startsWith("UPDATE iam_developer_operator SET failed_attempts"),
                eq(1),eq(Timestamp.from(now)),any(byte[].class));
    }

    private Jwt token(String realm) {
        Instant now=clock.instant();
        return Jwt.withTokenValue("synthetic-token").header("alg","RS256")
                .subject(UUID.randomUUID().toString()).claim("sid",UUID.randomUUID().toString())
                .claim("realm",realm).issuedAt(now.minusSeconds(60)).expiresAt(now.plusSeconds(60)).build();
    }
}
