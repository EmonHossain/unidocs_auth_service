package com.unidocs.auth.session.application;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import org.springframework.stereotype.Service;
import org.springframework.transaction.*;
import org.springframework.transaction.support.TransactionTemplate;

import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.session.domain.*;
import com.unidocs.auth.session.domain.UserSession;
import com.unidocs.auth.session.persistence.SessionRepository.Owner;
import com.unidocs.auth.session.persistence.SessionRepository;

/** Session identity stays immutable; any current account grant can sustain the umbrella session. */
@Service
public class SessionAccess {
    public record Context(UserSession session, SessionRepository.Owner owner, SessionAccountGrant grant, Instant now) { }
    private final SessionRepository sessions;
    private final Clock clock;
    private final TransactionTemplate transactions;
    public SessionAccess(SessionRepository sessions, Clock clock, PlatformTransactionManager manager) {
        this.sessions = sessions; this.clock = clock;
        transactions = new TransactionTemplate(manager);
        transactions.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
        transactions.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }
    public Optional<Context> context(UserSession session, UUID subject, Instant now) {
        if (!session.loginAccountId().equals(subject)) throw new AuthenticationFailure();
        if (!session.activeAt(now)) return Optional.empty();
        Owner owner = sessions.owner(session.accountGroupId()).orElse(null);
        if (owner == null) return Optional.empty();
        return sessions.liveGrant(session, null, now).map(grant -> new Context(session, owner, grant, now));
    }
    public <T> T execute(UUID sessionId, UUID subject, Function<Context, T> operation) {
        return executeForGroups(sessionId, subject, java.util.List.of(), operation);
    }
    public <T> T executeForGroups(UUID sessionId, UUID subject, java.util.List<UUID> otherGroups, Function<Context,T> operation) {
        T result = transactions.execute(status -> {
            UUID actorGroup = sessions.sessionGroup(sessionId).orElseThrow(AuthenticationFailure::new);
            java.util.TreeSet<UUID> groups = new java.util.TreeSet<>(java.util.Comparator.comparing(UUID::toString));
            groups.add(actorGroup); groups.addAll(otherGroups);
            for (UUID group : groups) sessions.lockGroup(group);
            UserSession session = sessions.lock(sessionId).orElseThrow(AuthenticationFailure::new);
            Instant now = clock.instant();
            Context context = context(session, subject, now).orElse(null);
            if (context == null) {
                sessions.revoke(session, null, now, "NO_USABLE_ACCOUNT");
                return null;
            }
            return operation.apply(context);
        });
        if (result == null) throw new AuthenticationFailure();
        return result;
    }
}
