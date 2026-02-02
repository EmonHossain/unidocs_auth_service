package com.unidocs.auth.group.domain;

import java.util.UUID;

public record GroupRule(UUID groupId, Discovery discovery, Joining joining, UUID departmentGroupId,
        UUID semesterId, long version) {
    public enum Discovery { ORGANIZATION, DEPARTMENT, INVITATION_ONLY }
    public enum Joining { OPEN, APPROVAL, INVITATION_ONLY, COURSE_ENROLLMENT }
}
