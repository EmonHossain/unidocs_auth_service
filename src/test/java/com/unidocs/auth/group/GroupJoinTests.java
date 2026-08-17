package com.unidocs.auth.group;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import com.unidocs.auth.group.api.GroupJoinRequests;
import com.unidocs.auth.group.domain.GroupJoinRequest;
import com.unidocs.auth.group.domain.GroupMembership;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class GroupJoinTests {
    @Mock JdbcTemplate jdbc;
    private final Instant now=Instant.parse("2026-10-02T12:00:00Z");
    @Test void reasonsAreBoundedAndHiddenFromCommandAndDomainStringRepresentations() {
        assertThat(GroupJoinRequest.normalizedReason(" Please approve ")).isEqualTo("Please approve");
        for(String invalid:new String[]{"", "x".repeat(501), "line\ncontrol"})
            assertThatThrownBy(()->GroupJoinRequest.normalizedReason(invalid)).isInstanceOf(IllegalArgumentException.class);
        GroupJoinRequests.Submit command=new GroupJoinRequests.Submit(UUID.randomUUID(),UUID.randomUUID(),"private-role","sensitive reason");
        assertThat(command.toString()).doesNotContain("private-role","sensitive reason");
        assertThat(new GroupJoinRequests.Review(UUID.randomUUID(),true,"private-role",now,null,"sensitive review").toString())
                .doesNotContain("private-role","sensitive review");
    }
    @Test void approvalSourcesRequireCanonicalRequestReferencesAndAssignmentSourcesRejectThem() {
        UUID request=UUID.randomUUID();
        GroupMembership membership=new GroupMembership(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),
                "member",GroupMembership.MembershipType.PERMANENT,GroupMembership.Source.ADMIN_APPROVAL,request.toString(),GroupMembership.Status.ACTIVE,now,null,1,now,now);
        assertThat(membership.sourceReference()).isEqualTo(request.toString());
        assertThatThrownBy(()->new GroupMembership(membership.id(),membership.organizationId(),membership.groupId(),membership.accountId(),membership.organizationMembershipId(),
                "member",membership.membershipType(),GroupMembership.Source.ORGANIZATION_ASSIGNMENT,request.toString(),membership.status(),now,null,1,now,now))
                .isInstanceOf(IllegalArgumentException.class);
    }
    @Test void joinOutboxCarriesStateVersionAndAnchorWithoutReasonsOrRequestedRole() {
        GroupJoinRequest request=new GroupJoinRequest(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),"sensitive-role",
                "private reason",GroupJoinRequest.Status.APPROVED,2,UUID.randomUUID(),now,"private review",UUID.randomUUID(),now,now);
        assertThat(request.toString()).doesNotContain("private","sensitive-role");
        new OutboxRepository(jdbc).groupJoinChanged(request,"GROUP_JOIN_APPROVED",now);
        ArgumentCaptor<Object[]> parameters=ArgumentCaptor.forClass(Object[].class);
        verify(jdbc).update(anyString(),parameters.capture());
        assertThat(parameters.getValue()[1]).isEqualTo("GROUP_JOIN_REQUEST");
        assertThat(parameters.getValue()[3]).isEqualTo(2L);
        assertThat((String)parameters.getValue()[5]).contains(request.organizationMembershipId().toString(),request.membershipId().toString(),"APPROVED")
                .doesNotContain("private reason","private review","sensitive-role");
    }
}
