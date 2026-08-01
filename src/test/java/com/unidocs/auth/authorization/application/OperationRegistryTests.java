package com.unidocs.auth.authorization.application;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class OperationRegistryTests {
    private final OperationRegistry registry = new OperationRegistry();
    @Test void professionalOperationsStayBoundToOwningServiceAndResourceKind() {
        assertThat(registry.require("auth-service","organization.employee.create","ORGANIZATION").key()).isEqualTo("organization.employee.create");
        assertThat(registry.require("document-service","publication.approve","FILE").key()).isEqualTo("publication.approve");
        assertThatThrownBy(()->registry.require("auth-service","publication.approve","FILE")).isInstanceOf(OperationAuthorizationFailure.class);
        assertThatThrownBy(()->registry.require("document-service","organization.employee.create","ORGANIZATION")).isInstanceOf(OperationAuthorizationFailure.class);
        assertThatThrownBy(()->registry.require("auth-service","team.access.update","ORGANIZATION")).isInstanceOf(OperationAuthorizationFailure.class);
    }
    @Test void callerCannotChooseAnotherServiceOrUnimplementedOperation() {
        assertThat(registry.require("document-service", "file.share.view", "FILE").key()).isEqualTo("file.share.view");
        assertThat(registry.require("document-service", "folder.share.view", "FOLDER").key()).isEqualTo("folder.share.view");
        assertThat(registry.require("document-service", "content.access.update", "FOLDER").key()).isEqualTo("content.access.update");
        assertThatThrownBy(() -> registry.require("document-service", "folder.share.edit", "FILE"))
                .isInstanceOf(OperationAuthorizationFailure.class);
        assertThatThrownBy(() -> registry.require("auth-service", "file.share", "FILE")).isInstanceOf(OperationAuthorizationFailure.class);
        assertThatThrownBy(() -> registry.require("document-service", "file.share", "GROUP")).isInstanceOf(OperationAuthorizationFailure.class);
        assertThatThrownBy(() -> registry.require("document-service", "file.superuser", "FILE")).isInstanceOf(OperationAuthorizationFailure.class);
    }
}
