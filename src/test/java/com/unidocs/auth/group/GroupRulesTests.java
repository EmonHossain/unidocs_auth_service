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
import com.unidocs.auth.group.persistence.GroupMembershipRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class GroupRulesTests {
    @Mock JdbcTemplate jdbc;
    private final Instant now=Instant.parse("2026-10-03T00:00:00Z");
    private GroupMembership membership(GroupMembership.Source source,String reference) {
        return new GroupMembership(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),"student",
                GroupMembership.MembershipType.TEMPORARY,source,reference,GroupMembership.Status.ACTIVE,now,now.plusSeconds(60),1,now,now);
    }
    @Test void trustedSourcesRequireCanonicalReferencesAndOpenJoiningCannotClaimOne() {
        for(GroupMembership.Source source:new GroupMembership.Source[]{GroupMembership.Source.COURSE_ENROLLMENT,GroupMembership.Source.INVITATION}) {
            assertThatThrownBy(()->membership(source,null)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(()->membership(source,"forged")).isInstanceOf(IllegalArgumentException.class);
            assertThat(membership(source,UUID.randomUUID().toString()).canManageGroup()).isFalse();
        }
        assertThatThrownBy(()->membership(GroupMembership.Source.OPEN_JOIN,UUID.randomUUID().toString())).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void enrollmentPersistsItsOwnSourceColumnAndVersionWithoutApprovalReference() {
        UUID enrollment=UUID.randomUUID();GroupMembership member=membership(GroupMembership.Source.COURSE_ENROLLMENT,enrollment.toString());
        new GroupMembershipRepository(jdbc).create(member,UUID.randomUUID(),UUID.randomUUID(),"fingerprint",3L);
        ArgumentCaptor<Object[]> args=ArgumentCaptor.forClass(Object[].class);verify(jdbc).update(anyString(),args.capture());
        assertThat(args.getValue()[15]).isNull();assertThat(args.getValue()[16]).isEqualTo(false);
        assertThat(args.getValue()[17]).isEqualTo(com.unidocs.auth.session.persistence.SessionRepository.bytes(enrollment));
        assertThat(args.getValue()[18]).isEqualTo(3L);assertThat(args.getValue()[19]).isNull();
    }
    @Test void enrollmentBatchCanPublishMembershipChangesWithOneSeparateOrganizationInvalidation() {
        GroupMembership member=membership(GroupMembership.Source.COURSE_ENROLLMENT,UUID.randomUUID().toString());
        new OutboxRepository(jdbc).groupMembershipChanged(member,42,"GROUP_MEMBER_ASSIGNED",now,false);
        ArgumentCaptor<Object[]> args=ArgumentCaptor.forClass(Object[].class);verify(jdbc,times(2)).update(anyString(),args.capture());
        Object[] event=args.getAllValues().stream().filter(values->values.length>5 && "GROUP_MEMBERSHIP".equals(values[1])).findFirst().orElseThrow();
        assertThat((String)event[5]).contains("\"organizationVersion\":42").doesNotContain("student");
    }
}

