package com.unidocs.auth.authorization.controlplane;

import java.util.UUID;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class ProfessionalReconciliationValidationTests {
    private final JdbcTemplate jdbc=mock(JdbcTemplate.class);
    private final DeveloperGate gate=mock(DeveloperGate.class);
    private final EntityManager entities=mock(EntityManager.class);
    private final PasswordEncoder passwords=mock(PasswordEncoder.class);
    private final OutboxRepository outbox=mock(OutboxRepository.class);
    private final ProfessionalReconciliationService service=new ProfessionalReconciliationService(jdbc,gate,entities,passwords,outbox);
    private final DeveloperCatalogService.Proof proof=new DeveloperCatalogService.Proof(UUID.randomUUID(),"synthetic-password","synthetic-factor");
    @Test void missingProofOrSourceCannotStartMigrationOrHashSecrets() {
        assertThatThrownBy(()->service.reconcile(null,null,UUID.randomUUID(),null)).isInstanceOf(ResponseStatusException.class);
        verifyNoInteractions(jdbc,gate,entities,passwords,outbox);
    }
    @Test void existingTargetCannotHaveItsPasswordSilentlyReplaced() {
        ProfessionalReconciliationService.Command command=new ProfessionalReconciliationService.Command(UUID.randomUUID(),UUID.randomUUID(),"synthetic-new-password",null,1);
        assertThatThrownBy(()->service.reconcile(null,proof,UUID.randomUUID(),command)).isInstanceOf(ResponseStatusException.class);
        verifyNoInteractions(jdbc,gate,entities,passwords,outbox);
    }
    @Test void newTargetRequiresExplicitValidCredentialAndName() {
        ProfessionalReconciliationService.Command command=new ProfessionalReconciliationService.Command(UUID.randomUUID(),null,"short","Employee",1);
        assertThatThrownBy(()->service.reconcile(null,proof,UUID.randomUUID(),command)).isInstanceOf(ResponseStatusException.class);
        verifyNoInteractions(jdbc,gate,entities,passwords,outbox);
    }
    @Test void commandAndRequestNeverRenderCredentialMaterial() {
        String password="synthetic-only-password";
        assertThat(new ProfessionalReconciliationService.Command(UUID.randomUUID(),null,password,"Employee",1).toString()).doesNotContain(password);
        assertThat(new ProfessionalReconciliationController.Request(UUID.randomUUID(),password,"synthetic-factor",UUID.randomUUID(),null,password,"Employee",1).toString()).doesNotContain(password,"synthetic-factor");
    }
}
