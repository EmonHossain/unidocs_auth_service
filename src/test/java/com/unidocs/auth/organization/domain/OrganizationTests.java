package com.unidocs.auth.organization.domain;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class OrganizationTests {
    @Test void rejectsInvalidNamesSlugsAndFingerprint() {
        for(String slug:new String[]{"a","UPPER","double--dash","-prefix","suffix-","a".repeat(64)})
            assertThatThrownBy(()->organization("Name",slug,"a".repeat(64))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->organization(" ","valid","a".repeat(64))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->organization("Name","valid","untrusted")).isInstanceOf(IllegalArgumentException.class);
        assertThat(organization(" Name ","valid-slug","a".repeat(64)).name()).isEqualTo("Name");
    }
    private Organization organization(String name,String slug,String fingerprint) {
        return new Organization(UUID.randomUUID(),name,slug,Organization.Type.COMPANY,UUID.randomUUID(),UUID.randomUUID(),fingerprint,Instant.now());
    }
}
