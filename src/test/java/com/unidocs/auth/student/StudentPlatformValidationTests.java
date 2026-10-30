package com.unidocs.auth.student;

import java.util.UUID;
import jakarta.validation.Validation;
import jakarta.validation.ValidatorFactory;
import com.unidocs.auth.account.lifecycle.LifecycleRepository;
import com.unidocs.auth.authorization.application.OperationAuthorizationFailure;
import com.unidocs.auth.authorization.controlplane.DeveloperCatalogService;
import com.unidocs.auth.authorization.controlplane.DeveloperGate;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.persistence.SessionRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class StudentPlatformValidationTests {
    private final ValidatorFactory validators=Validation.buildDefaultValidatorFactory();
    private final JdbcTemplate jdbc=mock(JdbcTemplate.class);
    private final DeveloperGate gate=mock(DeveloperGate.class);
    private final StudentWorkspaceService changes=mock(StudentWorkspaceService.class);
    private final LifecycleRepository lifecycle=mock(LifecycleRepository.class);
    private final SessionRepository sessions=mock(SessionRepository.class);
    private final OutboxRepository outbox=mock(OutboxRepository.class);
    private final StudentPlatformService service=new StudentPlatformService(jdbc,gate,changes,lifecycle,sessions,validators.getValidator(),outbox);
    @AfterEach void close() { validators.close(); }
    @Test void unverifiedInstitutionTerminationCannotBecomeAnEnforcementProof() {
        DeveloperCatalogService.Proof proof=new DeveloperCatalogService.Proof(UUID.randomUUID(),"synthetic-password","synthetic-second-factor");
        StudentPlatformService.ProofCommand command=new StudentPlatformService.ProofCommand(UUID.randomUUID(),UUID.randomUUID(),null,"STUDENTSHIP_TERMINATION","institution/case_123",false);
        assertThatThrownBy(()->service.verifyProof(null,proof,UUID.randomUUID(),command)).isInstanceOf(OperationAuthorizationFailure.class);
        verifyNoInteractions(jdbc,gate,changes,lifecycle,sessions,outbox);
    }
    @Test void missingDeveloperProofAndInvalidDecisionNeverReadOrRevokeTargetState() {
        assertThatThrownBy(()->service.enforce(null,null,UUID.randomUUID(),new StudentPlatformService.Decision(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),"REMOVE_TERMINATED",1))).isInstanceOf(OperationAuthorizationFailure.class);
        DeveloperCatalogService.Proof proof=new DeveloperCatalogService.Proof(UUID.randomUUID(),"synthetic-password","synthetic-second-factor");
        assertThatThrownBy(()->service.enforce(null,proof,UUID.randomUUID(),new StudentPlatformService.Decision(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),"EXPEL_BY_ROLE",1))).isInstanceOf(OperationAuthorizationFailure.class);
        verifyNoInteractions(jdbc,gate,changes,lifecycle,sessions,outbox);
    }
}
