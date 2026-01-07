package com.unidocs.auth.authorization.domain;

import java.util.Set;

/** Service-owned mandatory metadata. Editable policy cannot register executable operations. */
public record RegisteredOperation(String serviceId, String key, Set<String> resourceKinds) {
    public RegisteredOperation {
        resourceKinds = Set.copyOf(resourceKinds);
    }
}
