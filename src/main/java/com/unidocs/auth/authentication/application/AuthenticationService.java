package com.unidocs.auth.authentication.application;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.*;
import org.springframework.transaction.support.TransactionTemplate;

import io.micrometer.core.instrument.MeterRegistry;

import com.unidocs.auth.authentication.api.*;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.security.jwt.AccessTokens;
import com.unidocs.auth.security.bruteforce.LoginAttackProtection;
import com.unidocs.auth.session.application.SessionAccess.Context;
import com.unidocs.auth.session.domain.*;
import com.unidocs.auth.session.domain.RefreshSecret;
import com.unidocs.auth.session.domain.UserSession;
import com.unidocs.auth.session.persistence.SessionRepository.Account;
import com.unidocs.auth.session.persistence.SessionRepository.Identity;
import com.unidocs.auth.session.persistence.SessionRepository.Owner;
import com.unidocs.auth.session.persistence.SessionRepository.Refresh;
import com.unidocs.auth.session.persistence.SessionRepository;

@Service
@org.springframework.transaction.annotation.Transactional(propagation = org.springframework.transaction.annotation.Propagation.NEVER)
public class AuthenticationService {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(AuthenticationService.class);
    private final LoginAttackProtection protection;
    private final SessionRepository store;
    private final PasswordEncoder passwords;
    private final String dummyHash;
    private final AccessTokens tokens;
    private final Clock clock;
    private final TransactionTemplate transactions;
    private final MeterRegistry metrics;
    private final com.unidocs.auth.session.application.SessionAccess access;

    public AuthenticationService(SessionRepository store, PasswordEncoder passwords, AccessTokens tokens,
            Clock clock, PlatformTransactionManager transactionManager, MeterRegistry metrics,
            com.unidocs.auth.session.application.SessionAccess access, LoginAttackProtection protection) {
        this.protection = protection;
        this.store = store; this.passwords = passwords; this.tokens = tokens; this.clock = clock; this.metrics = metrics;
        this.access = access;
        dummyHash = passwords.encode(UUID.randomUUID().toString());
        transactions = new TransactionTemplate(transactionManager);
        transactions.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
        transactions.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    public TokenResponse login(LoginRequest request) {
        return login(request, "internal");
    }

    public TokenResponse login(LoginRequest request, String peer) {
        if (request == null || request.email() == null || request.email().length() > 254
                || request.email().isBlank() || request.password() == null || request.password().isBlank()
                || request.password().length() > 128) throw new AuthenticationFailure();
        String email = request.email().strip().toLowerCase(Locale.ROOT);
        return login(email,null,request.password(),peer);
    }

    public TokenResponse loginAccount(UUID accountId, AccountLoginRequest request) {
        return loginAccount(accountId, request, "internal");
    }

    public TokenResponse loginAccount(UUID accountId, AccountLoginRequest request, String peer) {
        if(accountId==null || request==null || request.password()==null || request.password().isBlank() || request.password().length()>128)
            throw new AuthenticationFailure();
        return login(null,accountId,request.password(),peer);
    }

    private TokenResponse login(String email, UUID accountId, String password, String peer) {
        Identity candidate = (accountId==null?store.identity(email,false):store.organizationIdentity(accountId,false)).orElse(null);
        String selector = candidate != null ? "account:" + candidate.accountId()
                : accountId != null ? "account:" + accountId : "email:" + email;
        return protection.protect(peer, selector, () -> authenticate(email, accountId, password, candidate));
    }

    private TokenResponse authenticate(String email, UUID accountId, String password, Identity candidate) {
        // The expensive password check runs outside the database transaction, including unknown identities.
        boolean matched = passwords.matches(password, candidate == null ? dummyHash : candidate.passwordHash());
        TokenResponse response = transactions.execute(status -> {
            if (candidate == null) {
                store.audit(null, null, "LOGIN_FAILED", clock.instant());
                return null;
            }
            // Use the same group-before-identity lock order as account proof and grant operations.
            store.lockGroup(candidate.groupId());
            store.owner(candidate.groupId());
            Identity current = (accountId==null?store.identity(email,true):store.organizationIdentity(accountId,true)).orElse(null);
            Instant now = clock.instant();
            if (!matched || candidate == null || current == null || !current.available()
                    || !current.id().equals(candidate.id()) || current.credentialVersion() != candidate.credentialVersion()
                    || !current.passwordHash().equals(candidate.passwordHash())) {
                store.audit(current, null, "LOGIN_FAILED", now);
                return null;
            }
            UserSession session = new UserSession(UUID.randomUUID(), current.groupId(), current.accountId(), "ACTIVE",
                    now, now, now.plus(UserSession.LIFETIME), null);
            RefreshSecret refresh = RefreshSecret.create();
            store.create(session, current, refresh, now);
            store.audit(current, session.id(), "LOGIN_SUCCEEDED", now);
            return response(session, refresh);
        });
        metrics.counter("authentication.login", "outcome", response == null ? "failed" : "succeeded").increment();
        // Emit only after the audit/business transaction commits; diagnostics carry no identity or secrets.
        LOG.atInfo().addKeyValue("event.action", response == null ? "auth.login.failed" : "auth.login.succeeded")
                .addKeyValue("event.category", List.of("authentication"))
                .addKeyValue("event.outcome", response == null ? "failure" : "success")
                .log("Authentication attempt completed");
        if (response == null) throw new AuthenticationFailure();
        return response;
    }

    public TokenResponse refresh(RefreshRequest request) {
        RefreshSecret supplied;
        try { supplied = RefreshSecret.parse(request == null ? null : request.refreshToken()); }
        catch (IllegalArgumentException exception) {
            transactions.executeWithoutResult(status -> store.audit(null, null, "REFRESH_FAILED", clock.instant()));
            metrics.counter("authentication.refresh", "outcome", "failed").increment();
            throw new AuthenticationFailure();
        }
        RefreshResult result;
        try {
            result = transactions.execute(status -> {
                RefreshResult decision = refreshDecision(supplied);
                if ("failed".equals(decision.outcome())) {
                    store.audit(null, null, "REFRESH_FAILED", clock.instant());
                }
                return decision;
            });
        } catch (AuthenticationFailure failure) {
            metrics.counter("authentication.refresh", "outcome", "failed").increment();
            throw failure;
        }
        metrics.counter("authentication.refresh", "outcome", result.outcome()).increment();
        if (result.response() == null) throw new AuthenticationFailure();
        return result.response();
    }

    private RefreshResult refreshDecision(RefreshSecret supplied) {
        UUID sessionId = store.refreshSession(supplied.id()).orElse(null);
        if (sessionId == null) return new RefreshResult(null, "failed");
        store.lockGroup(store.sessionGroup(sessionId).orElseThrow(AuthenticationFailure::new));
        UserSession session = store.lock(sessionId).orElseThrow(AuthenticationFailure::new);
        Refresh saved = store.refresh(supplied.id()).orElseThrow(AuthenticationFailure::new);
        if (!supplied.matches(saved.secretHash())) return new RefreshResult(null, "failed");
        Instant now = clock.instant();
        // A proven replay commits revocation before returning the generic 401 to the caller.
        if (saved.usedAt() != null) {
            store.owner(session.accountGroupId());
            Identity identity = store.accountIdentity(session.loginAccountId()).orElse(null);
            store.revoke(session, identity, now, "REFRESH_REPLAY");
            store.audit(identity, session.id(), "REFRESH_REPLAY", now);
            return new RefreshResult(null, "replay");
        }
        if (saved.revokedAt() != null) return new RefreshResult(null, "failed");
        Context context = access.context(session, session.loginAccountId(), now).orElse(null);
        if (context == null) {
            store.revoke(session, null, now, "NO_USABLE_ACCOUNT");
            return new RefreshResult(null, "failed");
        }
        if (!now.isBefore(saved.expiresAt())) return new RefreshResult(null, "failed");
        RefreshSecret replacement = RefreshSecret.create();
        store.rotate(saved, replacement, session, now);
        store.touch(session, context.grant(), now);
        return new RefreshResult(response(session, replacement), "succeeded");
    }

    public void logout(UUID sessionId, UUID subject) {
        transactions.executeWithoutResult(status -> {
            store.lockGroup(store.sessionGroup(sessionId).orElseThrow(AuthenticationFailure::new));
            UserSession session = store.lock(sessionId).orElseThrow(AuthenticationFailure::new);
            if (!session.loginAccountId().equals(subject)) throw new AuthenticationFailure();
            store.owner(session.accountGroupId());
            store.revoke(session, store.accountIdentity(subject).orElse(null), clock.instant(), "LOGOUT");
        });
        metrics.counter("authentication.session.revoked", "reason", "logout").increment();
    }

    public void logoutAll(UUID sessionId, UUID subject) {
        access.execute(sessionId, subject, context -> {
            store.revokeGroup(context.session().accountGroupId(), context.now());
            store.auditLogoutAll(context.owner().userId(), subject, sessionId,
                    context.session().accountGroupId(), context.now());
            return Boolean.TRUE;
        });
        metrics.counter("authentication.session.revoked", "reason", "logout_all").increment();
    }

    public record Me(UUID userId, String displayName, UUID sessionId, UUID loginAccountId, UUID preferredAccountId) { }
    public Me me(UUID sessionId, UUID subject) {
        return access.execute(sessionId, subject, context -> {
            store.touch(context.session(), context.grant(), context.now());
            Owner owner = context.owner();
            return new Me(owner.userId(), owner.displayName(), context.session().id(), subject, owner.preferredAccountId());
        });
    }

    public record AccountPage(List<SessionRepository.Account> accounts, UUID nextCursor) { }
    public AccountPage accounts(UUID sessionId, UUID subject, UUID after, int limit) {
        if (limit < 1 || limit > 100) throw new IllegalArgumentException("Invalid page size.");
        return access.execute(sessionId, subject, context -> {
            store.touch(context.session(), context.grant(), context.now());
            List<Account> accounts = store.accounts(context.session(), after, limit + 1, context.now());
            boolean more = accounts.size() > limit;
            List<Account> page = List.copyOf(accounts.subList(0, Math.min(limit, accounts.size())));
            return new AccountPage(page, more ? page.getLast().id() : null);
        });
    }

    private record RefreshResult(TokenResponse response, String outcome) { }
    private TokenResponse response(UserSession session, RefreshSecret refresh) {
        return new TokenResponse("Bearer", tokens.issue(session.loginAccountId(), session.id()),
                AccessTokens.LIFETIME.toSeconds(), refresh.value(), session.id(), session.loginAccountId());
    }
}

