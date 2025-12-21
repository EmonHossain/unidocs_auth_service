package com.unidocs.auth.authorization.application;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** Makes missing graph configuration a startup failure for selected content checks. */
@Component
@ConditionalOnProperty(prefix = "auth.spicedb.canary", name = "content-enabled", havingValue = "true")
final class ProfessionalSpiceDbContentGuard {
    /**
     * Requires the canary and its configured permission client.
     * @param canary required organization canary
     * @throws IllegalArgumentException when graph configuration is absent
     */
    ProfessionalSpiceDbContentGuard(ProfessionalSpiceDbCanary canary) {
        if (canary == null) throw new IllegalArgumentException("Content checks require the SpiceDB canary.");
    }
}
