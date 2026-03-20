package com.unidocs.auth.registration.application;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import jakarta.validation.Validator;

import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import io.micrometer.core.instrument.MeterRegistry;

import com.unidocs.auth.authentication.domain.LoginIdentity;
import com.unidocs.auth.authentication.persistence.LoginIdentityRepository;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.domain.*;
import com.unidocs.auth.registration.domain.PendingRegistration;
import com.unidocs.auth.registration.domain.ProvisionedIdentity;
import com.unidocs.auth.registration.domain.RegistrationVerification;
import com.unidocs.auth.registration.persistence.*;

@Service
public class RegistrationProvisioningService {
    private final PendingRegistrationRepository registrations;
    private final RegistrationVerificationRepository verifications;
    private final LoginIdentityRepository loginIdentities;
    private final CoreIdentityRepository identities;
    private final VerificationTokens tokens;
    private final Clock clock;
    private final Validator validator;
    private final MeterRegistry metrics;
    private final TransactionTemplate transactions;

    public RegistrationProvisioningService(PendingRegistrationRepository registrations,
            RegistrationVerificationRepository verifications, LoginIdentityRepository loginIdentities,
            CoreIdentityRepository identities, VerificationTokens tokens, Clock clock, Validator validator,
            MeterRegistry metrics, PlatformTransactionManager transactionManager) {
        this.registrations = registrations;
        this.verifications = verifications;
        this.loginIdentities = loginIdentities;
        this.identities = identities;
        this.tokens = tokens;
        this.clock = clock;
        this.validator = validator;
        this.metrics = metrics;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    @Transactional(propagation = Propagation.NEVER)
    public RegistrationCompletionResponse complete(UUID id, RegistrationCompletionRequest request) {
        if (id == null || request == null || !validator.validate(request).isEmpty()) {
            count("invalid");
            throw new RegistrationException(HttpStatus.BAD_REQUEST);
        }
        try {
            CompletionResult result = transactions.execute(transaction -> {
                PendingRegistration registration = registrations.findForUpdate(id)
                        .orElseThrow(() -> new RegistrationException(HttpStatus.BAD_REQUEST));
                RegistrationVerification verification = verifications.findByPendingRegistrationId(id)
                        .orElseThrow(() -> new RegistrationException(HttpStatus.BAD_REQUEST));
                Instant now = clock.instant().truncatedTo(ChronoUnit.MICROS);
                if (verification.status() != VerificationStatus.VERIFIED
                        || !tokens.matches(request.token(), verification.tokenHash())
                        || !now.isBefore(registration.expiresAt())) {
                    throw new RegistrationException(HttpStatus.BAD_REQUEST);
                }
                if (registration.status() == RegistrationStatus.COMPLETED) {
                    return new CompletionResult(response(registration), "replayed");
                }
                if (registration.status() != RegistrationStatus.VERIFIED) {
                    throw new RegistrationException(HttpStatus.BAD_REQUEST);
                }
                if (loginIdentities.existsByTypeAndIdentifier(LoginIdentity.Type.EMAIL, registration.identifier())) {
                    throw new RegistrationException(HttpStatus.CONFLICT);
                }
                ProvisionedIdentity identity = ProvisionedIdentity.fromVerified(registration, now);
                identities.persist(identity);
                registration.complete(identity, now);
                return new CompletionResult(response(registration), "success");
            });
            count(result.outcome());
            return result.response();
        } catch (DataIntegrityViolationException exception) {
            // Resolve races at the unique index after the entire provisioning transaction rolls back.
            for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
                if (cause instanceof ConstraintViolationException constraint
                        && constraint.getConstraintName() != null
                        && constraint.getConstraintName().endsWith("uq_login_identity_identifier")) {
                    count("conflict");
                    throw new RegistrationException(HttpStatus.CONFLICT);
                }
            }
            count("failure");
            throw exception;
        } catch (RegistrationException exception) {
            count(exception.status() == HttpStatus.CONFLICT ? "conflict" : "invalid");
            throw exception;
        } catch (RuntimeException exception) {
            count("failure");
            throw exception;
        }
    }

    private void count(String outcome) { metrics.counter("registration.provisioning", "outcome", outcome).increment(); }

    private static RegistrationCompletionResponse response(PendingRegistration registration) {
        return new RegistrationCompletionResponse(registration.id(), registration.status(), registration.provisionedUserId(),
                registration.provisionedAccountId(), registration.provisionedAccountGroupId(), registration.completedAt());
    }

    private record CompletionResult(RegistrationCompletionResponse response, String outcome) { }
}
