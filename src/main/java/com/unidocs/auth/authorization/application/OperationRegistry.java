package com.unidocs.auth.authorization.application;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.unidocs.auth.authorization.domain.RegisteredOperation;
import org.springframework.stereotype.Component;

@Component
public class OperationRegistry {
    private final Map<String, RegisteredOperation> operations;

    public OperationRegistry() {
        Map<String, RegisteredOperation> definitions = new HashMap<>();
        register(definitions,"auth-service","ORGANIZATION",List.of("student.admission.review","course.catalog.read",
                "course.catalog.create","course.catalog.update","course.catalog.remove","semester.create","course.join",
                "student.report.submit","student.report.review","student.report.evidence.submit","study.group.create"));
        register(definitions, "document-service", "FILE", List.of("file.read", "file.download", "file.create",
                "file.edit", "file.collaborative.edit", "file.copy", "file.move", "file.rename", "file.delete.schedule",
                "file.restore", "file.share", "file.share.view", "file.share.edit", "file.share.revoke", "content.access.update"));
        register(definitions, "document-service", "FOLDER", List.of("folder.read", "folder.create", "folder.rename",
                "folder.move", "folder.copy", "folder.delete.schedule", "folder.restore", "folder.share",
                "folder.share.view", "folder.share.edit", "folder.share.revoke"));
        register(definitions, "document-service", "WORKSPACE", List.of("workspace.create", "workspace.read", "quota.read", "deletion.read"));
        register(definitions, "auth-service", "GROUP", List.of("group.create", "group.read", "group.invitation.issue",
                "group.invitation.accept", "group.invitation.decline", "group.invitation.revoke", "group.member.remove",
                "group.leave", "group.delete.schedule", "group.delete.cancel"));
        register(definitions,"auth-service","ORGANIZATION",List.of("organization.employee.create","organization.employee.remove",
                "organization.employee.reset","organization.responsibility.assign","organization.access.update","organization.group.create"));
        register(definitions,"auth-service","GROUP",List.of("organization.department.assign","organization.group.assign",
                "organization.group.unassign","department.access.update","team.access.update","organization.collaboration.invite"));
        register(definitions,"document-service","FILE",List.of("publication.submit","publication.approve","publication.reject",
                "publication.read","publication.edit.own","publication.delete.schedule"));
        register(definitions,"document-service","WORKSPACE",List.of("organization.quota.read","organization.deletion.policy.update"));
        // Existing resource viewers may read a workspace/group listing; actual visibility remains Document-owned.
        for (String key : List.of("workspace.read", "quota.read", "deletion.read")) {
            definitions.put(key, new RegisteredOperation("document-service", key, Set.of("WORKSPACE", "GROUP")));
        }
        definitions.put("content.access.update", new RegisteredOperation("document-service", "content.access.update", Set.of("FILE", "FOLDER")));
        operations = Map.copyOf(definitions);
    }

    public RegisteredOperation require(String serviceId, String key, String resourceKind) {
        RegisteredOperation operation = operations.get(key);
        if (operation == null || !operation.serviceId().equals(serviceId) || !operation.resourceKinds().contains(resourceKind)) {
            throw new OperationAuthorizationFailure(org.springframework.http.HttpStatus.FORBIDDEN, "UNREGISTERED_OPERATION");
        }
        return operation;
    }

    public Map<String, RegisteredOperation> definitions() { return operations; }

    private static void register(Map<String, RegisteredOperation> definitions, String service, String kind, List<String> keys) {
        for (String key : keys) definitions.put(key, new RegisteredOperation(service, key, Set.of(kind)));
    }
}
