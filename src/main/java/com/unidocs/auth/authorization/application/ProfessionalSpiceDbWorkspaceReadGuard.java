package com.unidocs.auth.authorization.application;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** Prevents a selected workspace-read canary from silently starting without its graph boundary. */
@Component
@ConditionalOnProperty(prefix = "auth.spicedb.canary", name = "workspace-read-enabled", havingValue = "true")
final class ProfessionalSpiceDbWorkspaceReadGuard {
    /**
     * Requires the configured canary and its permission client at application startup.
     * @param canary required organization canary
     * @throws IllegalArgumentException when the canary is absent
     */
    ProfessionalSpiceDbWorkspaceReadGuard(ProfessionalSpiceDbCanary canary) {
        if (canary == null) throw new IllegalArgumentException("Workspace-read checks require the SpiceDB canary.");
    }
}
