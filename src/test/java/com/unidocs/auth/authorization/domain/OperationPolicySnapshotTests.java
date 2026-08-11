package com.unidocs.auth.authorization.domain;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OperationPolicySnapshotTests {
    private final UUID operationId = UUID.randomUUID();
    private final UUID policyId = UUID.randomUUID();
    private final UUID roleId = UUID.randomUUID();
    private final UUID firstAuthorityId = UUID.randomUUID();
    private final UUID secondAuthorityId = UUID.randomUUID();
    private final OperationAuthorityPolicy policy = new OperationAuthorityPolicy(
            Set.of(firstAuthorityId, secondAuthorityId), AuthorityMatchMode.ALL_OF, true);
    private final Map<UUID, Long> versions = Map.of(firstAuthorityId, 1L, secondAuthorityId, 2L);

    @Test
    void acceptsCategorySubsetAndCopiesCollections() {
        Set<UUID> category = new HashSet<>(Set.of(firstAuthorityId));
        Map<UUID, Long> mutableVersions = new HashMap<>(versions);
        OperationPolicySnapshot snapshot = snapshot(category, mutableVersions);
        category.clear();
        mutableVersions.clear();

        assertThat(snapshot.categoryAuthorityIds()).containsExactly(firstAuthorityId);
        assertThat(snapshot.authorityVersions()).isEqualTo(versions);
        assertThat(snapshot.policy()).isEqualTo(policy);
        assertThatThrownBy(() -> snapshot.categoryAuthorityIds().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> snapshot.authorityVersions().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(snapshot(Set.of(), versions).categoryAuthorityIds()).isEmpty();
    }

    @Test
    void rejectsMissingExtraAndUnrelatedAuthorities() {
        assertThatThrownBy(() -> snapshot(Set.of(), Map.of(firstAuthorityId, 1L)))
                .isInstanceOf(IllegalArgumentException.class);
        Map<UUID, Long> extraVersions = new HashMap<>(versions);
        extraVersions.put(UUID.randomUUID(), 1L);
        assertThatThrownBy(() -> snapshot(Set.of(), extraVersions)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> snapshot(Set.of(UUID.randomUUID()), versions))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(longs = {0, -1})
    void rejectsNonpositiveVersions(long version) {
        assertThatThrownBy(() -> snapshot(Set.of(), Map.of(firstAuthorityId, version, secondAuthorityId, 2L)))
                .isInstanceOf(IllegalArgumentException.class);
        for (int position = 0; position < 4; position++) {
            long[] input = {1, 1, 1, 1};
            input[position] = version;
            assertThatThrownBy(() -> new OperationPolicySnapshot(operationId, "auth-service", "account.unlock",
                    input[0], policyId, input[1], "INDIVIDUAL", input[2], roleId, input[3], policy,
                    Set.of(), versions)).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "Auth", "auth..service", " auth", "auth ", "a/b"})
    void rejectsUnstableOperationAndServiceKeys(String key) {
        assertThatThrownBy(() -> new OperationPolicySnapshot(operationId, key, "account.unlock", 1,
                policyId, 1, "INDIVIDUAL", 1, roleId, 1, policy, Set.of(), versions))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OperationPolicySnapshot(operationId, "auth-service", key, 1,
                policyId, 1, "INDIVIDUAL", 1, roleId, 1, policy, Set.of(), versions))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", " INDIVIDUAL", "INDIVIDUAL "})
    void rejectsBlankOrPaddedCategoryKeys(String categoryKey) {
        assertThatThrownBy(() -> new OperationPolicySnapshot(operationId, "auth-service", "account.unlock", 1,
                policyId, 1, categoryKey, 1, roleId, 1, policy, Set.of(), versions))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNullIdentitiesKeysPolicyAndCollections() {
        for (int position = 0; position < 7; position++) {
            Object[] input = {operationId, "auth-service", "account.unlock", policyId, "INDIVIDUAL", roleId, policy};
            input[position] = null;
            assertThatThrownBy(() -> new OperationPolicySnapshot((UUID) input[0], (String) input[1],
                    (String) input[2], 1, (UUID) input[3], 1, (String) input[4], 1, (UUID) input[5], 1,
                    (OperationAuthorityPolicy) input[6], Set.of(), versions)).isInstanceOf(NullPointerException.class);
        }
        assertThatThrownBy(() -> snapshot(null, versions)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> snapshot(Set.of(), null)).isInstanceOf(NullPointerException.class);
        Set<UUID> nullCategory = new HashSet<>();
        nullCategory.add(null);
        assertThatThrownBy(() -> snapshot(nullCategory, versions)).isInstanceOf(NullPointerException.class);
        Map<UUID, Long> nullVersion = new HashMap<>(versions);
        nullVersion.put(firstAuthorityId, null);
        assertThatThrownBy(() -> snapshot(Set.of(), nullVersion)).isInstanceOf(NullPointerException.class);
    }

    private OperationPolicySnapshot snapshot(Set<UUID> category, Map<UUID, Long> authorityVersions) {
        return new OperationPolicySnapshot(operationId, "auth-service", "account.unlock", 1, policyId, 1,
                "INDIVIDUAL", 1, roleId, 1, policy, category, authorityVersions);
    }
}
