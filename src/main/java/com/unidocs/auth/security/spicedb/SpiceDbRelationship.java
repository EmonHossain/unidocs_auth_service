package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.ObjectReference;
import com.authzed.api.v1.Relationship;
import com.authzed.api.v1.RelationshipUpdate;
import com.authzed.api.v1.SubjectReference;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

record SpiceDbRelationship(String resourceType, String resourceId, String relation,
        String subjectType, String subjectId) implements Comparable<SpiceDbRelationship> {
    SpiceDbRelationship {
        if (blank(resourceType) || blank(resourceId) || blank(relation) || blank(subjectType) || blank(subjectId)) {
            throw new IllegalArgumentException("relationship fields must be nonempty.");
        }
    }

    String hash() {
        String canonical = String.join("\u001f", resourceType, resourceId, relation, subjectType, subjectId);
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is required by the Java runtime.", impossible);
        }
    }

    RelationshipUpdate update(RelationshipUpdate.Operation operation) {
        Relationship relationship = Relationship.newBuilder()
                .setResource(ObjectReference.newBuilder().setObjectType(resourceType).setObjectId(resourceId))
                .setRelation(relation)
                .setSubject(SubjectReference.newBuilder().setObject(
                        ObjectReference.newBuilder().setObjectType(subjectType).setObjectId(subjectId)))
                .build();
        return RelationshipUpdate.newBuilder().setOperation(operation).setRelationship(relationship).build();
    }

    @Override
    public int compareTo(SpiceDbRelationship other) {
        return hash().compareTo(other.hash());
    }

    private static boolean blank(String value) { return value == null || value.isBlank(); }
}
