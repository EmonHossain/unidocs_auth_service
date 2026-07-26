package com.unidocs.auth.authentication.application;
import java.time.Clock;
import java.util.Optional;
import java.util.UUID;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.TransactionStatus;
import com.unidocs.auth.authentication.api.*;
import com.unidocs.auth.security.bruteforce.LoginAttackProtection;
import com.unidocs.auth.security.jwt.AccessTokens;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.persistence.SessionRepository;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.*;
@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTests {
    @Mock SessionRepository store;
    @Mock PasswordEncoder passwords;
    @Mock AccessTokens tokens;
    @Mock PlatformTransactionManager manager;
    @Mock SessionAccess access;
    @Mock LoginAttackProtection protection;
    AuthenticationService service;
    @BeforeEach void setup() {
        when(passwords.encode(anyString())).thenReturn("dummy");
        service=new AuthenticationService(store,passwords,tokens,Clock.systemUTC(),manager,new SimpleMeterRegistry(),access,protection);
    }
    @Test void unknownEmailUsesCanonicalSelectorAndDenialPrecedesPasswordWork() {
        when(store.identity("unknown@example.com",false)).thenReturn(Optional.empty());
        when(protection.protect(eq("192.0.2.1"),eq("email:unknown@example.com"),any())).thenThrow(new AuthenticationFailure());
        assertThatThrownBy(()->service.login(new LoginRequest(" UNKNOWN@EXAMPLE.COM ","password"),"192.0.2.1")).isInstanceOf(AuthenticationFailure.class);
        verify(passwords,never()).matches(anyString(),anyString());
        verifyNoInteractions(manager,tokens);
    }
    @Test void missingRefreshRequestAuditsBeforeReturningGenericFailure() {
        TransactionStatus transaction = mock(TransactionStatus.class);
        when(manager.getTransaction(any())).thenReturn(transaction);
        assertThatThrownBy(() -> service.refresh(null)).isInstanceOf(AuthenticationFailure.class);
        org.mockito.InOrder order = inOrder(store, manager);
        order.verify(manager).getTransaction(any());
        order.verify(store).audit(isNull(),isNull(),eq("REFRESH_FAILED"),any());
        order.verify(manager).commit(transaction);
        verifyNoInteractions(tokens, access);
    }
    @Test void malformedRefreshAuditPersistenceFailureRollsBack() {
        TransactionStatus transaction = mock(TransactionStatus.class);
        when(manager.getTransaction(any())).thenReturn(transaction);
        doThrow(new IllegalStateException("test-only")).when(store)
                .audit(isNull(),isNull(),eq("REFRESH_FAILED"),any());
        assertThatThrownBy(() -> service.refresh(new RefreshRequest("malformed")))
                .isInstanceOf(IllegalStateException.class);
        verify(manager).rollback(transaction);
        verify(manager, never()).commit(any());
        verifyNoInteractions(tokens, access);
    }
    @Test void knownEmailUsesStableAccountSelector() {
        UUID account=UUID.randomUUID();
        SessionRepository.Identity candidate=new SessionRepository.Identity(UUID.randomUUID(),account,UUID.randomUUID(),UUID.randomUUID(),account,"User","hash",1,true);
        when(store.identity("user@example.com",false)).thenReturn(Optional.of(candidate));
        when(protection.protect(eq("192.0.2.1"),eq("account:"+account),any())).thenThrow(new AuthenticationFailure());
        assertThatThrownBy(()->service.login(new LoginRequest("user@example.com","password"),"192.0.2.1")).isInstanceOf(AuthenticationFailure.class);
        verify(passwords,never()).matches(anyString(),anyString());
        verifyNoInteractions(manager,tokens);
    }
    @Test void unknownDirectAccountUsesSameAccountSelector() {
        UUID account=UUID.randomUUID();
        when(store.organizationIdentity(account,false)).thenReturn(Optional.empty());
        when(protection.protect(eq("192.0.2.1"),eq("account:"+account),any())).thenThrow(new AuthenticationFailure());
        assertThatThrownBy(()->service.loginAccount(account,new AccountLoginRequest("password"),"192.0.2.1")).isInstanceOf(AuthenticationFailure.class);
        verify(passwords,never()).matches(anyString(),anyString());
        verifyNoInteractions(manager,tokens);
    }
    @Test void failedLoginEmitsSafeDiagnosticOnlyAfterAuditTransactionCommits() {
        String email = "private-user@example.com";
        String password = "private-password";
        when(store.identity(email,false)).thenReturn(Optional.empty());
        when(protection.protect(eq("192.0.2.1"),eq("email:"+email),any())).thenAnswer(invocation -> {
            Supplier<TokenResponse> action = invocation.getArgument(2);
            return action.get();
        });
        TransactionStatus transaction = mock(TransactionStatus.class);
        when(manager.getTransaction(any())).thenReturn(transaction);
        AtomicBoolean committed = new AtomicBoolean();
        Logger logger = (Logger) LoggerFactory.getLogger(AuthenticationService.class);
        Level previousLevel = logger.getLevel();
        ListAppender<ILoggingEvent> appender = new ListAppender<>() {
            @Override protected void append(ILoggingEvent event) {
                assertThat(committed.get()).isTrue();
                super.append(event);
            }
        };
        appender.start();
        logger.setLevel(Level.INFO);
        logger.addAppender(appender);
        doAnswer(invocation -> {
            assertThat(appender.list).isEmpty();
            committed.set(true);
            return null;
        }).when(manager).commit(transaction);
        try {
            assertThatThrownBy(() -> service.login(new LoginRequest(email,password),"192.0.2.1"))
                    .isInstanceOf(AuthenticationFailure.class);
            verify(store).audit(isNull(),isNull(),eq("LOGIN_FAILED"),any());
            verify(manager).commit(transaction);
            assertThat(appender.list).hasSize(1);
            ILoggingEvent event = appender.list.getFirst();
            assertThat(event.getFormattedMessage()).isEqualTo("Authentication attempt completed");
            assertThat(event.getKeyValuePairs()).extracting(pair -> pair.key)
                    .containsExactly("event.action", "event.category", "event.outcome");
            assertThat(event.getKeyValuePairs()).extracting(pair -> pair.value)
                    .containsExactly("auth.login.failed", List.of("authentication"), "failure");
            assertThat(event.getFormattedMessage() + event.getKeyValuePairs())
                    .doesNotContain(email,password,"dummy");
            assertThat(event.getThrowableProxy()).isNull();
            assertThat(event.getArgumentArray()).isNullOrEmpty();
        } finally {
            logger.detachAppender(appender);
            logger.setLevel(previousLevel);
            appender.stop();
        }
    }
}

