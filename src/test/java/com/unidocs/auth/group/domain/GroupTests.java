package com.unidocs.auth.group.domain;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class GroupTests {
    @Test void groupNormalizesNameWithoutCreatingMembershipOrChangingParent() {
        UUID id = UUID.randomUUID();
        Group group = new Group(id, UUID.randomUUID(), null, " Engineering ", Group.Type.DEPARTMENT,
                UUID.randomUUID(), UUID.randomUUID(), "a".repeat(64), Instant.now());
        assertThat(group.name()).isEqualTo("Engineering");
        assertThat(group.parentGroupId()).isNull();
    }
    @Test void groupRejectsSelfParentAndInvalidName() {
        UUID id = UUID.randomUUID();
        assertThatThrownBy(() -> new Group(id, UUID.randomUUID(), id, "Engineering", Group.Type.TEAM,
                UUID.randomUUID(), UUID.randomUUID(), "a".repeat(64), Instant.now())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Group.normalizedName("\n")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Group.normalizedName("x".repeat(101))).isInstanceOf(IllegalArgumentException.class);
    }
}
