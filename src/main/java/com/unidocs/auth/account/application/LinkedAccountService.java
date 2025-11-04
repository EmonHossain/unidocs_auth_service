package com.unidocs.auth.account.application;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import io.micrometer.core.instrument.MeterRegistry;

import com.unidocs.auth.account.api.*;
import com.unidocs.auth.account.domain.AccountChallenge.*;
import com.unidocs.auth.account.domain.AccountChallenge;
import com.unidocs.auth.account.persistence.AccountAccessRepository.*;
import com.unidocs.auth.account.persistence.AccountAccessRepository.Proof;
import com.unidocs.auth.account.persistence.AccountAccessRepository.Target;
import com.unidocs.auth.account.persistence.AccountAccessRepository;
import com.unidocs.auth.credential.application.AccountProofVerifier;
import com.unidocs.auth.session.application.SessionAccess.Context;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.domain.SessionGrantPolicy;
import com.unidocs.auth.session.persistence.SessionRepository;

@Service
@org.springframework.transaction.annotation.Transactional(propagation = org.springframework.transaction.annotation.Propagation.NEVER)
public class LinkedAccountService {
    private final SessionAccess access;
    private final SessionRepository sessions;
    private final AccountAccessRepository accounts;
    private final List<AccountProofVerifier> verifiers;
    private final PasswordEncoder encoder;
    private final String dummyHash;
    private final MeterRegistry metrics;

    public LinkedAccountService(SessionAccess access, SessionRepository sessions, AccountAccessRepository accounts,
            List<AccountProofVerifier> verifiers, PasswordEncoder encoder, MeterRegistry metrics) {
        this.access = access;
        this.sessions = sessions;
        this.accounts = accounts;
        this.verifiers = verifiers;
        this.encoder = encoder;
        this.metrics = metrics;
        dummyHash = encoder.encode(UUID.randomUUID().toString());
    }

    public record ChallengeResponse(UUID id, UUID accountId, Purpose purpose, Method method, Instant expiresAt) {
    }

    public record ActionResponse(UUID accountId, Purpose purpose, boolean unlocked, boolean sessionRevoked,
            UUID preferredAccountId, Instant idleExpiresAt, Instant absoluteExpiresAt) {
    }

    public ChallengeResponse challenge(UUID sid, UUID subject, UUID accountId, ChallengeRequest request) {
        if (request == null || request.purpose() == null || request.method() == null
                || verifiers.stream().noneMatch(verifier -> verifier.supports(request.method())))
            throw new AccountAccessDenied();
        return access.execute(sid, subject, actor -> {
            Target target = target(actor, accountId, request.purpose());
            if (request.method() == Method.PIN && !target.pinAllowed())
                throw new AccountAccessDenied();
            if (request.purpose() == Purpose.SET_PIN && (request.method() != Method.PASSWORD
                    || sessions.liveGrant(actor.session(), target.id(), actor.now()).isEmpty()))
                throw new AccountAccessDenied();
            Proof proof = accounts.proof(target.id(), request.method(), true).filter(p -> p.usableAt(actor.now()))
                    .orElseThrow(AccountAccessDenied::new);
            AccountChallenge challenge = accounts.createChallenge(actor, target, request.purpose(), request.method(),
                    proof, sessions.policy());
            return new ChallengeResponse(challenge.id(), challenge.accountId(), challenge.purpose(), challenge.method(),
                    challenge.expiresAt());
        });
    }

    public ActionResponse complete(UUID sid, UUID subject, UUID accountId, UUID challengeId,
            AccountProofRequest request) {
        if (request == null || request.secret() == null || request.secret().isBlank()
                || request.secret().length() > 128)
            throw new AccountAccessDenied();
        AccountChallenge candidate = accounts.challenge(challengeId, false).orElseThrow(AccountAccessDenied::new);
        // Bind the public selector before doing expensive proof work; it is never a
        // bearer capability.
        if (!candidate.sessionId().equals(sid) || !candidate.accountId().equals(accountId))
            throw new AccountAccessDenied();
        if (candidate.purpose() == Purpose.SET_PIN) {
            if (request.newPin() == null || !request.newPin().matches("[0-9]{6,12}"))
                throw new AccountAccessDenied();
        } else if (request.newPin() != null)
            throw new AccountAccessDenied();
        Proof before = accounts.proof(accountId, candidate.method(), false).orElse(null);
        AccountProofVerifier verifier = verifiers.stream().filter(v -> v.supports(candidate.method())).findFirst()
                .orElseThrow(AccountAccessDenied::new);
        boolean matched = verifier.verify(candidate.method(), request.secret(),
                before == null ? dummyHash : before.hash());
        String pinHash = matched && candidate.purpose() == Purpose.SET_PIN ? encoder.encode(request.newPin()) : null;
        Completion result = access.execute(sid, subject, actor -> {
            AccountChallenge challenge = accounts.challenge(challengeId, true).orElseThrow(AccountAccessDenied::new);
            if (!challenge.sessionId().equals(sid) || !challenge.accountId().equals(accountId))
                throw new AccountAccessDenied();
            if (!challenge.pendingAt(actor.now())) {
                if ("PENDING".equals(challenge.status()) && !actor.now().isBefore(challenge.expiresAt()))
                    accounts.expire(challenge);
                return new Completion(null);
            }
            Target target = target(actor, accountId, challenge.purpose());
            if (challenge.method() == Method.PIN && !target.pinAllowed())
                throw new AccountAccessDenied();
            Proof current = accounts.proof(accountId, challenge.method(), true).orElse(null);
            SessionGrantPolicy policy = sessions.policy();
            if (before == null || current == null || !current.usableAt(actor.now())
                    || !current.id().equals(challenge.credentialId())
                    || !current.id().equals(before.id()) || current.version() != challenge.credentialVersion()
                    || current.version() != before.version() || !current.hash().equals(before.hash())
                    || !current.source().equals(challenge.credentialSource())
                    || challenge.policyVersion() != policy.version()) {
                return new Completion(null);
            }
            if (!matched) {
                accounts.failure(challenge, current, actor.now());
                sessions.audit(actor.owner().userId(), accountId, sid, "ACCOUNT_UNLOCK_FAILED", actor.now());
                return new Completion(null);
            }
            accounts.consume(challenge, actor.now());
            switch (challenge.purpose()) {
                case UNLOCK -> {
                    accounts.grant(actor, current, challenge.method(), policy);
                    sessions.audit(actor.owner().userId(), accountId, sid, "ACCOUNT_UNLOCKED", actor.now());
                }
                case LINK -> {
                    accounts.link(actor, target, challenge.method());
                    sessions.audit(actor.owner().userId(), accountId, sid, "ACCOUNT_LINKED", actor.now());
                }
                case UNLINK -> {
                    accounts.unlink(actor, target);
                    sessions.audit(actor.owner().userId(), accountId, sid, "ACCOUNT_UNLINKED", actor.now());
                }
                case SET_PIN -> {
                    if (challenge.method() != Method.PASSWORD
                            || sessions.liveGrant(actor.session(), target.id(), actor.now()).isEmpty())
                        throw new AccountAccessDenied();
                    accounts.setPin(accountId, pinHash, actor.now());
                    // Preserve an existing LOGIN/PASSWORD grant; freshly proved password can
                    // replace an invalidated PIN grant.
                    if (sessions.liveGrant(actor.session(), accountId, actor.now()).isEmpty())
                        accounts.grant(actor, current, Method.PASSWORD, policy);
                    sessions.audit(actor.owner().userId(), accountId, sid, "PIN_CHANGED", actor.now());
                }
            }
            SessionAccountGrant live = sessions.liveGrant(actor.session(), null, actor.now()).orElse(null);
            boolean revoked = live == null;
            if (revoked)
                sessions.revoke(actor.session(), null, actor.now(), "NO_USABLE_ACCOUNT");
            else
                sessions.touch(actor.session(), live, actor.now());
            SessionAccountGrant grant = sessions.liveGrant(actor.session(), accountId, actor.now()).orElse(null);
            UUID preferred = sessions.owner(actor.session().accountGroupId())
                    .map(SessionRepository.Owner::preferredAccountId).orElse(null);
            return new Completion(new ActionResponse(accountId, challenge.purpose(), grant != null, revoked, preferred,
                    grant == null ? null : grant.idleExpiresAt(), grant == null ? null : grant.absoluteExpiresAt()));
        });
        metrics.counter("account.challenge", "outcome", result.response() == null ? "failed" : "succeeded", "purpose",
                candidate.purpose().name()).increment();
        if (result.response() == null)
            throw new AccountAccessDenied();
        return result.response();
    }

    private record Completion(ActionResponse response) {
    }

    public UUID preferred(UUID sid, UUID subject, UUID accountId) {
        return access.execute(sid, subject, actor -> {
            target(actor, accountId, Purpose.UNLOCK);
            accounts.preferred(actor, accountId);
            sessions.audit(actor.owner().userId(), accountId, sid, "PREFERENCE_CHANGED", actor.now());
            return accountId;
        });
    }

    private Target target(Context actor, UUID accountId, Purpose purpose) {
        Target target = accounts.target(accountId).orElseThrow(AccountAccessDenied::new);
        if (!actor.owner().userId().equals(target.userId()) || !"ACTIVE".equals(target.accountStatus())
                || !target.organizationAvailable())
            throw new AccountAccessDenied();
        if (purpose == Purpose.LINK) {
            if ("LINKED".equals(target.linkStatus())
                    || (target.groupId() != null && !target.groupId().equals(actor.session().accountGroupId())))
                throw new AccountAccessDenied();
        } else if (!"LINKED".equals(target.linkStatus()) || !actor.session().accountGroupId().equals(target.groupId()))
            throw new AccountAccessDenied();
        return target;
    }
}
