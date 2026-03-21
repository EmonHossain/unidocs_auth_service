package com.unidocs.auth.registration.application;

import java.time.*;
import java.util.Locale;
import java.util.UUID;

import jakarta.validation.Validator;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import io.micrometer.core.instrument.MeterRegistry;

import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.domain.*;
import com.unidocs.auth.registration.domain.PendingRegistration;
import com.unidocs.auth.registration.domain.RegistrationVerification;
import com.unidocs.auth.registration.persistence.*;

@Service
public class RegistrationService {
    private static final Duration REGISTRATION_LIFETIME = Duration.ofHours(24);
    private static final Duration VERIFICATION_LIFETIME = Duration.ofMinutes(5);
    private final PendingRegistrationRepository registrations;
    private final RegistrationVerificationRepository verifications;
    private final PasswordEncoder passwords;
    private final VerificationTokens tokens;
    private final ObjectProvider<VerificationDelivery> delivery;
    private final Clock clock;
    private final TransactionTemplate transactions;
    private final Validator validator;
    private final MeterRegistry metrics;

    public RegistrationService(PendingRegistrationRepository registrations,
            RegistrationVerificationRepository verifications, PasswordEncoder passwords,
            VerificationTokens tokens, ObjectProvider<VerificationDelivery> delivery, Clock clock,
            PlatformTransactionManager transactionManager, Validator validator, MeterRegistry metrics) {
        this.registrations = registrations;
        this.verifications = verifications;
        this.passwords = passwords;
        this.tokens = tokens;
        this.delivery = delivery;
        this.clock = clock;
        this.transactions = new TransactionTemplate(transactionManager);
        this.validator = validator;
        this.metrics = metrics;
    }

    @Transactional(propagation = Propagation.NEVER)
    public RegistrationResponse register(RegistrationRequest request) {
        validate(request);
        VerificationDelivery provider = delivery.getIfAvailable();
        if (provider == null) {
            throw new RegistrationException(HttpStatus.SERVICE_UNAVAILABLE);
        }
        String email = request.email().strip().toLowerCase(Locale.ROOT);
        String displayName = request.displayName().strip();
        String passwordHash = passwords.encode(request.password());
        String token = tokens.generate();
        Instant now = clock.instant();
        Instant tokenExpiry = now.plus(VERIFICATION_LIFETIME);
        UUID id = UUID.randomUUID();
        RegistrationResponse response = transactions.execute(status -> {
            PendingRegistration registration = registrations.save(new PendingRegistration(id, displayName, email,
                    passwordHash, now, now.plus(REGISTRATION_LIFETIME)));
            verifications.save(new RegistrationVerification(UUID.randomUUID(), id, email,
                    tokens.hash(token), now, tokenExpiry));
            return response(registration);
        });
        // The transaction is committed before any SMTP network call.
        try {
            provider.deliver(email, id, token, tokenExpiry);
        } catch (RuntimeException exception) {
            metrics.counter("registration.delivery", "outcome", "failure").increment();
            throw new RegistrationException(HttpStatus.SERVICE_UNAVAILABLE);
        }
        metrics.counter("registration.created").increment();
        return response;
    }

    @Transactional(propagation = Propagation.NEVER)
    public RegistrationResponse verify(UUID id, VerificationRequest request) {
        validate(request);
        if (id == null) { throw new RegistrationException(HttpStatus.BAD_REQUEST); }
        // Return failures from inside the transaction so attempts/expiration commit before throwing.
        VerificationResult result = transactions.execute(status -> {
            PendingRegistration registration = registrations.findForUpdate(id).orElse(null);
            if (registration == null) { return new VerificationResult(null, "invalid"); }
            RegistrationVerification verification = verifications.findByPendingRegistrationId(id).orElseThrow();
            Instant now = clock.instant();
            boolean registrationExpired = registration.expireIfNecessary(now);
            boolean verificationExpired = verification.expireIfNecessary(now);
            if (registrationExpired || verificationExpired) {
                return new VerificationResult(null, "expired");
            }
            if (registration.status() != RegistrationStatus.PENDING_VERIFICATION
                    || !verification.attempt(tokens.matches(request.token(), verification.tokenHash()), now)) {
                return new VerificationResult(null, "invalid");
            }
            registration.verify(now);
            return new VerificationResult(response(registration), "success");
        });
        metrics.counter("registration.verification", "outcome", result.outcome()).increment();
        if (result.response() == null) { throw new RegistrationException(HttpStatus.BAD_REQUEST); }
        return result.response();
    }

    private void validate(Object request) {
        if (request == null || !validator.validate(request).isEmpty()) {
            throw new RegistrationException(HttpStatus.BAD_REQUEST);
        }
    }

    private static RegistrationResponse response(PendingRegistration registration) {
        return new RegistrationResponse(registration.id(), registration.status(), registration.expiresAt());
    }

    private record VerificationResult(RegistrationResponse response, String outcome) { }
}
