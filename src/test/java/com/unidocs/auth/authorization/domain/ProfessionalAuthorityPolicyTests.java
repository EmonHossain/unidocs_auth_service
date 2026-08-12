package com.unidocs.auth.authorization.domain;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static com.unidocs.auth.authorization.domain.ProfessionalAuthorityPolicy.*;
import static org.assertj.core.api.Assertions.*;

class ProfessionalAuthorityPolicyTests {
    private final UUID org = UUID.randomUUID();
    private final UUID department = UUID.randomUUID();
    private final UUID account = UUID.randomUUID();
    private final UUID operation = UUID.randomUUID();
    private final UUID authority = UUID.randomUUID();
    private final UUID alternative = UUID.randomUUID();
    private final Instant now = Instant.parse("2026-10-16T12:00:00Z");
    private final Scope organizationScope = new Scope(org, null, null);
    private final Scope departmentScope = new Scope(org, department, null);
    private final Scope team = new Scope(org, department, UUID.randomUUID());
    private final OperationAuthorityPolicy policy = new OperationAuthorityPolicy(Set.of(authority), AuthorityMatchMode.ALL_OF, true);

    @Test
    void applicableAncestorOrExactAssignmentCanSupplyAuthority() {
        for (Scope scope : List.of(organizationScope, departmentScope, team)) {
            assertThat(matches(policy, List.of(grant(account, scope, now, null)), List.of())).isTrue();
        }
        assertThat(matches(policy, List.of(), List.of())).isFalse();
    }

    @ParameterizedTest
    @EnumSource(AuthorityMatchMode.class)
    void everyApplicableAncestorDenyDefeatsTeamGrantAndAnyAlternative(AuthorityMatchMode mode) {
        OperationAuthorityPolicy alternatives = new OperationAuthorityPolicy(Set.of(authority, alternative), mode, true);
        Assignment grant = new Assignment(account, team, Set.of(authority, alternative), now, null);
        assertThat(ProfessionalAuthorityPolicy.matches(alternatives, operation, account, team,
                Set.of(authority, alternative), List.of(grant), List.of(), now, true)).isTrue();
        for (Scope scope : List.of(organizationScope, departmentScope, team)) {
            assertThat(ProfessionalAuthorityPolicy.matches(alternatives, operation, account, team,
                    Set.of(authority, alternative), List.of(grant),
                    List.of(deny(operation, null, scope, now, null)), now, true)).isFalse();
        }
    }

    @Test
    void unrelatedBranchesOtherOrganizationsAndLinkedAccountsCannotGrant() {
        for (Assignment assignment : List.of(
                grant(account, new Scope(UUID.randomUUID(), null, null), now, null),
                grant(account, new Scope(org, UUID.randomUUID(), null), now, null),
                grant(account, new Scope(org, department, UUID.randomUUID()), now, null),
                grant(UUID.randomUUID(), organizationScope, now, null))) {
            assertThat(matches(policy, List.of(assignment), List.of())).isFalse();
        }
    }

    @Test
    void unrelatedOperationAccountOrScopeDenyDoesNotApply() {
        for (Restriction restriction : List.of(
                deny(UUID.randomUUID(), null, organizationScope, now, null),
                deny(operation, UUID.randomUUID(), organizationScope, now, null),
                deny(operation, null, new Scope(org, UUID.randomUUID(), null), now, null),
                deny(operation, null, new Scope(UUID.randomUUID(), null, null), now, null))) {
            assertThat(matches(policy, List.of(grant(account, team, now, null)), List.of(restriction))).isTrue();
        }
        assertThat(matches(policy, List.of(grant(account, team, now, null)),
                List.of(deny(operation, account, organizationScope, now, null)))).isFalse();
    }

    @Test
    void grantAndDenyWindowsUseInclusiveStartAndExclusiveExpiry() {
        assertThat(matches(policy, List.of(grant(account, team, now.plusSeconds(1), null)), List.of())).isFalse();
        assertThat(matches(policy, List.of(grant(account, team, now.minusSeconds(1), now)), List.of())).isFalse();
        List<Assignment> grants = List.of(grant(account, team, now, null));
        assertThat(matches(policy, grants, List.of(deny(operation, null, organizationScope, now.plusSeconds(1), null)))).isTrue();
        assertThat(matches(policy, grants, List.of(deny(operation, null, organizationScope, now.minusSeconds(1), now)))).isTrue();
        assertThat(matches(policy, grants, List.of(deny(operation, null, organizationScope, now, now.plusSeconds(1))))).isFalse();
    }

    @Test
    void splitWitnessAndMissingCategoryCannotAuthorize() {
        OperationAuthorityPolicy any = new OperationAuthorityPolicy(Set.of(authority, alternative), AuthorityMatchMode.ANY_OF, true);
        assertThat(matches(any, List.of(new Assignment(account, team, Set.of(alternative), now, null)), List.of())).isFalse();
        assertThat(ProfessionalAuthorityPolicy.matches(policy, operation, account, team, Set.of(),
                List.of(grant(account, team, now, null)), List.of(), now, true)).isFalse();
    }

    @Test
    void incompleteOrIncoherentEvidenceAndCategoryOnlyPoliciesDeny() {
        List<Assignment> grants = List.of(grant(account, team, now, null));
        assertThat(ProfessionalAuthorityPolicy.matches(policy, operation, account, team, Set.of(authority), grants, List.of(), now, false)).isFalse();
        assertThat(ProfessionalAuthorityPolicy.matches(policy, operation, account, null, Set.of(authority), grants, List.of(), now, true)).isFalse();
        assertThat(matches(new OperationAuthorityPolicy(Set.of(authority), AuthorityMatchMode.ALL_OF, false), grants, List.of())).isFalse();
    }

    @Test
    void malformedScopeAndInvalidValidityIntervalsAreRejected() {
        assertThatThrownBy(() -> new Scope(org, null, UUID.randomUUID())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Scope(null, department, null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> grant(account, team, now, now)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> deny(operation, null, team, now, now.minusSeconds(1))).isInstanceOf(IllegalArgumentException.class);
    }

    private Assignment grant(UUID actor, Scope scope, Instant from, Instant until) {
        return new Assignment(actor, scope, Set.of(authority), from, until);
    }

    private Restriction deny(UUID key, UUID actor, Scope scope, Instant from, Instant until) {
        return new Restriction(key, actor, scope, from, until);
    }

    private boolean matches(OperationAuthorityPolicy required, List<Assignment> grants, List<Restriction> restrictions) {
        return ProfessionalAuthorityPolicy.matches(required, operation, account, team, Set.of(authority), grants, restrictions, now, true);
    }
}
