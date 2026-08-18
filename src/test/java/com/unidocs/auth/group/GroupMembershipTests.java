package com.unidocs.auth.group;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import com.unidocs.auth.group.domain.GroupMembership;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class GroupMembershipTests {
    @Mock JdbcTemplate jdbc;
    private final Instant now = Instant.parse("2026-10-02T12:00:00Z");
    private GroupMembership member(Instant until, GroupMembership.Status status) {
        return new GroupMembership(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),
                "course-assistant",until == null ? GroupMembership.MembershipType.PERMANENT : GroupMembership.MembershipType.TEMPORARY,
                GroupMembership.Source.ORGANIZATION_ASSIGNMENT,null,status,now,until,1,now,now);
    }
    @Test void windowsUseInclusiveStartAndExclusiveEndWithoutScheduledExpiry() {
        GroupMembership membership = member(now.plusSeconds(1), GroupMembership.Status.ACTIVE);
        assertThat(membership.effectiveAt(now.minusNanos(1))).isFalse();
        assertThat(membership.effectiveAt(now)).isTrue();
        assertThat(membership.effectiveAt(now.plusSeconds(1))).isFalse();
        assertThat(member(null,GroupMembership.Status.ACTIVE).effectiveAt(now.plusSeconds(10000))).isTrue();
        assertThat(member(null,GroupMembership.Status.REVOKED).effectiveAt(now)).isFalse();
        assertThatThrownBy(() -> member(now,GroupMembership.Status.ACTIVE)).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void rolesAreCustomStringsAndRejectControlCharactersOrOverlongValues() {
        assertThat(GroupMembership.normalizedRole(" teaching-assistant ")).isEqualTo("teaching-assistant");
        for (String invalid : new String[]{"", "role\nadmin", "role with spaces", "a".repeat(65)}) {
            assertThatThrownBy(() -> GroupMembership.normalizedRole(invalid)).isInstanceOf(IllegalArgumentException.class);
        }
    }
    @Test void outboxCarriesBothVersionScopesAndValidityWithoutRoleOrNames() {
        GroupMembership membership = member(now.plusSeconds(30),GroupMembership.Status.ACTIVE);
        new OutboxRepository(jdbc).groupMembershipChanged(membership,42,"GROUP_MEMBER_ASSIGNED",now);
        ArgumentCaptor<Object[]> parameters = ArgumentCaptor.forClass(Object[].class);
        verify(jdbc,times(4)).update(anyString(),parameters.capture());
        java.util.List<Object[]> events=parameters.getAllValues().stream()
                .filter(values->values.length>5 && ("GROUP_MEMBERSHIP".equals(values[1]) || "ORGANIZATION".equals(values[1]))).toList();
        assertThat(events).hasSize(2);
        Object[] membershipEvent = events.getFirst();
        assertThat(membershipEvent[1]).isEqualTo("GROUP_MEMBERSHIP");
        assertThat(membershipEvent[3]).isEqualTo(1L);
        assertThat((String)membershipEvent[5]).contains("\"organizationVersion\":42",membership.organizationMembershipId().toString(),
                "\"validUntil\":\"2026-10-02T12:00:30Z\"").doesNotContain("course-assistant");
        Object[] organizationEvent = events.getLast();
        assertThat(organizationEvent[1]).isEqualTo("ORGANIZATION");
        assertThat(organizationEvent[3]).isEqualTo(42L);
        assertThat(organizationEvent[4]).isEqualTo("ORGANIZATION_GROUP_MEMBERSHIP_CHANGED");
    }
}
