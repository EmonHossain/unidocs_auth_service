package com.unidocs.auth.authorization.domain;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OperationAuthorityPolicyTests {
    private final UUID firstAuthorityId = UUID.randomUUID();
    private final UUID secondAuthorityId = UUID.randomUUID();
    private final Set<UUID> required = Set.of(firstAuthorityId, secondAuthorityId);

    @Test
    void allOfRequiresEveryAuthorityAtBothLayers() {
        OperationAuthorityPolicy policy = new OperationAuthorityPolicy(required, AuthorityMatchMode.ALL_OF, true);

        assertThat(policy.matches(evidence(required, required))).isTrue();
        assertThat(policy.matches(evidence(required, Set.of(firstAuthorityId)))).isFalse();
        assertThat(policy.matches(evidence(Set.of(firstAuthorityId), required))).isFalse();
    }

    @Test
    void anyOfRequiresTheSameAlternativeAtBothLayers() {
        OperationAuthorityPolicy policy = new OperationAuthorityPolicy(required, AuthorityMatchMode.ANY_OF, true);

        assertThat(policy.matches(evidence(Set.of(firstAuthorityId), Set.of(secondAuthorityId)))).isFalse();
        assertThat(policy.matches(evidence(required, Set.of(secondAuthorityId)))).isTrue();
    }

    @ParameterizedTest
    @EnumSource(AuthorityMatchMode.class)
    void anApplicableDenyDefeatsEveryAlternative(AuthorityMatchMode matchMode) {
        OperationAuthorityPolicy policy = new OperationAuthorityPolicy(required, matchMode, true);

        assertThat(policy.matches(new OperationAuthorityEvidence(required, required, true, true))).isFalse();
    }

    @ParameterizedTest
    @EnumSource(AuthorityMatchMode.class)
    void missingOrIncoherentEvidenceFailsClosed(AuthorityMatchMode matchMode) {
        OperationAuthorityPolicy policy = new OperationAuthorityPolicy(required, matchMode, true);

        assertThat(policy.matches(null)).isFalse();
        assertThat(policy.matches(new OperationAuthorityEvidence(required, required, false, false))).isFalse();
        assertThat(policy.matches(evidence(Set.of(), required))).isFalse();
        assertThat(policy.matches(evidence(required, Set.of()))).isFalse();
        assertThat(policy.matches(evidence(Set.of(UUID.randomUUID()), Set.of(UUID.randomUUID())))).isFalse();
    }

    @ParameterizedTest
    @EnumSource(AuthorityMatchMode.class)
    void categoryOnlyPolicyStillRequiresCategoryAuthorities(AuthorityMatchMode matchMode) {
        OperationAuthorityPolicy policy = new OperationAuthorityPolicy(required, matchMode, false);

        assertThat(policy.matches(evidence(required, Set.of()))).isTrue();
        assertThat(policy.matches(evidence(Set.of(), required))).isFalse();
        assertThat(policy.matches(evidence(Set.of(firstAuthorityId), Set.of())))
                .isEqualTo(matchMode == AuthorityMatchMode.ANY_OF);
    }

    @Test
    void policyAndEvidenceDefensivelyCopyAuthoritySets() {
        Set<UUID> mutable = new HashSet<>(required);
        OperationAuthorityPolicy policy = new OperationAuthorityPolicy(mutable, AuthorityMatchMode.ALL_OF, true);
        OperationAuthorityEvidence evidence = evidence(mutable, mutable);
        mutable.clear();

        assertThat(policy.matches(evidence)).isTrue();
        assertThatThrownBy(() -> policy.requiredAuthorityIds().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> evidence.categoryAuthorityIds().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> evidence.scopedAuthorityIds().clear()).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void policyRequiresNonemptyBoundedAuthoritiesAndAMatchingMode() {
        Set<UUID> maximum = IntStream.range(0, OperationAuthorityPolicy.MAX_REQUIRED_AUTHORITIES)
                .mapToObj(index -> new UUID(0, index)).collect(Collectors.toSet());
        Set<UUID> oversized = new HashSet<>(maximum);
        oversized.add(UUID.randomUUID());

        assertThat(new OperationAuthorityPolicy(maximum, AuthorityMatchMode.ALL_OF, true).requiredAuthorityIds())
                .hasSize(OperationAuthorityPolicy.MAX_REQUIRED_AUTHORITIES);
        assertThatThrownBy(() -> new OperationAuthorityPolicy(Set.of(), AuthorityMatchMode.ALL_OF, true))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OperationAuthorityPolicy(oversized, AuthorityMatchMode.ALL_OF, true))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OperationAuthorityPolicy(null, AuthorityMatchMode.ALL_OF, true))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new OperationAuthorityPolicy(required, null, true))
                .isInstanceOf(NullPointerException.class);
        Set<UUID> withNull = new HashSet<>(required);
        withNull.add(null);
        assertThatThrownBy(() -> new OperationAuthorityPolicy(withNull, AuthorityMatchMode.ALL_OF, true))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> evidence(null, required)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> evidence(required, null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> evidence(withNull, required)).isInstanceOf(NullPointerException.class);
    }

    private OperationAuthorityEvidence evidence(Set<UUID> category, Set<UUID> scoped) {
        return new OperationAuthorityEvidence(category, scoped, true, false);
    }
}
