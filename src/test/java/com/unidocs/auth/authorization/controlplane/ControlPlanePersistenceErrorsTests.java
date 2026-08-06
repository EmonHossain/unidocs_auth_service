package com.unidocs.auth.authorization.controlplane;

import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.DataIntegrityViolationException;
import static org.assertj.core.api.Assertions.*;

class ControlPlanePersistenceErrorsTests {
    private final ControlPlanePersistenceErrors errors=new ControlPlanePersistenceErrors();
    @Test void databaseUnavailabilityIs503WithBoundedRetryWithoutDiagnostics(){
        org.springframework.http.ResponseEntity<org.springframework.http.ProblemDetail> result=errors.unavailable(new DataAccessResourceFailureException("secret JDBC credentials"));
        assertThat(result.getStatusCode().value()).isEqualTo(503);
        assertThat(result.getHeaders().getFirst("Retry-After")).isEqualTo("1");
        assertThat(result.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        assertThat(result.getBody().toString()).doesNotContain("secret","JDBC","credentials");
    }
    @Test void duplicateMutationConflictIs409WithoutConstraintDiagnostics(){
        org.springframework.http.ResponseEntity<org.springframework.http.ProblemDetail> result=errors.conflict(new DataIntegrityViolationException("private constraint/password"));
        assertThat(result.getStatusCode().value()).isEqualTo(409);
        assertThat(result.getBody().toString()).doesNotContain("private","constraint","password");
    }
}
