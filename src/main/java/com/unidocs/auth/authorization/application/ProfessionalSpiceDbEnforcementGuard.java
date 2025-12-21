package com.unidocs.auth.authorization.application;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** Requires the graph canary to exist whenever graph-authoritative management is configured. */
@Component
@ConditionalOnProperty(prefix = "auth.spicedb.canary", name = "enforcement-enabled", havingValue = "true")
final class ProfessionalSpiceDbEnforcementGuard {
    ProfessionalSpiceDbEnforcementGuard(ProfessionalSpiceDbCanary canary) {
        if (canary == null) throw new IllegalArgumentException("Graph enforcement requires the SpiceDB canary.");
    }
}
