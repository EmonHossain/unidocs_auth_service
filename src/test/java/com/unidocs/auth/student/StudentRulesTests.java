package com.unidocs.auth.student;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.*;

class StudentRulesTests {
    private final Instant now=Instant.parse("2026-10-16T12:00:00Z");
    @ParameterizedTest
    @ValueSource(strings={"file.share","file.share.view","file.share.edit","folder.share","folder.share.view","folder.share.edit",
            "content.access.update","file.collaborative.edit","group.invitation.issue","group.invitation.accept","study.group.create"})
    void restrictionBlocksEveryCollaborationEntryPoint(String operation) {
        assertThat(StudentRules.permits("COLLABORATION_RESTRICTED",operation)).isFalse();
        assertThat(StudentRules.permits("ACTIVE",operation)).isTrue();
    }
    @ParameterizedTest
    @ValueSource(strings={"file.read","file.download","file.create","file.edit","file.rename","file.move","file.copy",
            "file.delete.schedule","folder.create","folder.rename","folder.delete.schedule","file.share.revoke","folder.share.revoke",
            "group.invitation.decline","group.leave","course.join","quota.read","deletion.read"})
    void restrictionPreservesSelfContainedRights(String operation) {
        assertThat(StudentRules.permits("COLLABORATION_RESTRICTED",operation)).isTrue();
    }
    @ParameterizedTest
    @ValueSource(strings={"REMOVED_INTRUDER","REMOVED_TERMINATED","PENDING_REVIEW","EMAIL_PENDING","UNKNOWN"})
    void unadmittedAndRemovedStatesNeverAuthorize(String state) {
        assertThat(StudentRules.permits(state,"file.read")).isFalse();
        assertThat(StudentRules.permits(state,"file.create")).isFalse();
    }
    @Test void joiningRequiresBothReadinessAndCurrentOfferingWindow() {
        assertThat(StudentRules.joinable("OFFERED","READY",now,now.plusSeconds(60),now)).isTrue();
        assertThat(StudentRules.joinable("OFFERED","PENDING",now,now.plusSeconds(60),now)).isFalse();
        assertThat(StudentRules.joinable("DRAFT","READY",now,now.plusSeconds(60),now)).isFalse();
        assertThat(StudentRules.joinable("RETIRED","READY",now,now.plusSeconds(60),now)).isFalse();
        assertThat(StudentRules.joinable("FINALIZED","READY",now.minusSeconds(60),now,now)).isFalse();
        assertThat(StudentRules.joinable("OFFERED","READY",now.plusSeconds(1),now.plusSeconds(60),now)).isFalse();
    }
    @Test void finalizedAndOngoingCatalogEntriesAreImmutable() {
        assertThat(StudentRules.catalogMutable("DRAFT",now.plusSeconds(1),now)).isTrue();
        assertThat(StudentRules.catalogMutable("OFFERED",now,now)).isFalse();
        assertThat(StudentRules.catalogMutable("FINALIZED",now.plusSeconds(1),now)).isFalse();
        assertThat(StudentRules.catalogMutable("RETIRED",now.plusSeconds(1),now)).isFalse();
    }
    @Test void deletionDeadlineClosesCopyAtTheExactBoundary() {
        assertThat(StudentRules.groupAvailable("PREPARING",null,"file.copy",now)).isTrue();
        assertThat(StudentRules.groupAvailable("PREPARING",null,"file.create",now)).isFalse();
        assertThat(StudentRules.groupAvailable("CLOSING",now.plusSeconds(1),"file.copy",now)).isTrue();
        assertThat(StudentRules.groupAvailable("CLOSING",now,"file.copy",now)).isFalse();
        assertThat(StudentRules.groupAvailable("CLOSING",now.plusSeconds(1),"file.edit",now)).isFalse();
    }
    @Test void recommendationsAndPolicyViolationsCannotRemoveLegitimateStudents() {
        assertThat(StudentRules.validDecision("RESTRICT","POLICY_VIOLATION",false)).isFalse();
        assertThat(StudentRules.validDecision("RESTRICT","POLICY_VIOLATION",true)).isTrue();
        assertThat(StudentRules.validDecision("REVERSE","POLICY_VIOLATION",true)).isTrue();
        assertThat(StudentRules.validDecision("REMOVE_TERMINATED","POLICY_VIOLATION",true)).isFalse();
        assertThat(StudentRules.validDecision("REMOVE_INTRUDER","POLICY_VIOLATION",true)).isFalse();
        assertThat(StudentRules.validDecision("REMOVE_TERMINATED","STUDENTSHIP_TERMINATION",false)).isTrue();
        assertThat(StudentRules.validDecision("REMOVE_INTRUDER","INTRUDER",true)).isTrue();
    }
    @Test void studentAdminInventoryContainsNoManagementOrContentAuthority() {
        assertThat(StudentRules.ADMIN_OPERATIONS).doesNotContain("course.join","organization.employee.remove","organization.group.assign",
                "student.enforcement.restrict","acl.role.update","file.read","file.create","study.group.create");
    }
}
