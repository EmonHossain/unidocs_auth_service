package com.unidocs.auth.authorization.controlplane;

import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import static org.assertj.core.api.Assertions.*;

class DeveloperCatalogValidationTests {
    @Test void strongPreconditionsAreMandatory(){
        assertThatThrownBy(()->DeveloperCatalogService.expected(null,1)).isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode()).isEqualTo(HttpStatus.PRECONDITION_REQUIRED));
        for(String value:List.of("1","W/\"1\"","*","\"0\"","\"2\""))
            assertThatThrownBy(()->DeveloperCatalogService.expected(value,1)).isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode()).isEqualTo(HttpStatus.PRECONDITION_FAILED));
        DeveloperCatalogService.expected("\"1\"",1);
    }
    @Test void rejectsEmptyOversizedDuplicateAndNullRequirements(){
        UUID authority=UUID.randomUUID();
        assertThatThrownBy(()->DeveloperCatalogService.validateAuthorities(List.of(),true)).isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(()->DeveloperCatalogService.validateAuthorities(Collections.nCopies(65,authority),false)).isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(()->DeveloperCatalogService.validateAuthorities(List.of(authority,authority),false)).isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(()->DeveloperCatalogService.validateAuthorities(Arrays.asList(authority,null),false)).isInstanceOf(ResponseStatusException.class);
        DeveloperCatalogService.validateAuthorities(List.of(),false);
        DeveloperCatalogService.validateAuthorities(List.of(authority),true);
    }
    @Test void secretDtosRedactAllProofMaterial(){
        assertThat(new DeveloperCatalogService.Proof(UUID.randomUUID(),"password","factor").toString()).isEqualTo("Proof[REDACTED]");
        assertThat(new DeveloperCatalogController.CatalogRequest(UUID.randomUUID(),"password","factor","roles",null,10).toString()).doesNotContain("password","factor");
    }
}
