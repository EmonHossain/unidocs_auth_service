package com.unidocs.auth.student;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import jakarta.validation.Validation;
import jakarta.validation.ValidatorFactory;
import com.unidocs.auth.authorization.application.OperationAuthorizationFailure;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class StudentValidationTests {
    private final ValidatorFactory validators=Validation.buildDefaultValidatorFactory();
    private final JdbcTemplate jdbc=mock(JdbcTemplate.class);
    private final SessionAccess access=mock(SessionAccess.class);
    private final StudentAuthorization authority=mock(StudentAuthorization.class);
    private final OutboxRepository outbox=mock(OutboxRepository.class);
    private final Instant now=Instant.parse("2026-10-16T12:00:00Z");
    private final StudentWorkspaceService service=new StudentWorkspaceService(jdbc,access,authority,outbox,validators.getValidator(),Clock.fixed(now,ZoneOffset.UTC));
    @AfterEach void close() { validators.close(); }
    @Test void invalidSemesterDoesNotStartAnAuthorizationOrProvisioningTransaction() {
        UUID account=UUID.randomUUID();UUID organization=UUID.randomUUID();
        assertThatThrownBy(()->service.semester(null,organization,new StudentWorkspaceService.SemesterCommand(account,"2026",now,now))).isInstanceOf(OperationAuthorizationFailure.class);
        assertThatThrownBy(()->service.semester(null,organization,new StudentWorkspaceService.SemesterCommand(account,"2026",now,now.plusNanos(1)))).isInstanceOf(OperationAuthorizationFailure.class);
        verifyNoInteractions(jdbc,access,authority,outbox);
    }
    @Test void evidenceReferencesCannotContainUrlsTraversalOrControlCharacters() {
        for(String reference:java.util.List.of("https://example.test/private","../secret","evidence/../secret","evidence\nprivate")) {
            assertThatThrownBy(()->StudentWorkspaceService.evidence(reference)).isInstanceOf(OperationAuthorizationFailure.class);
        }
        assertThatCode(()->StudentWorkspaceService.evidence("institution/proof_123-456")).doesNotThrowAnyException();
    }
    @Test void invalidReviewAndPaginationNeverReadPrivateReports() {
        assertThatThrownBy(()->service.reports(null,UUID.randomUUID(),UUID.randomUUID(),null,101)).isInstanceOf(OperationAuthorizationFailure.class);
        assertThatThrownBy(()->service.review(null,UUID.randomUUID(),UUID.randomUUID(),new StudentWorkspaceService.ReviewCommand(null,0,"reference",true))).isInstanceOf(OperationAuthorizationFailure.class);
        verifyNoInteractions(jdbc,access,authority,outbox);
    }
    @Test void evidenceAndProofRequestsRedactTheirStringRepresentations() {
        StudentWorkspaceService.ReportCommand report=new StudentWorkspaceService.ReportCommand(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),"private-evidence-reference");
        StudentPlatformService.ProofCommand proof=new StudentPlatformService.ProofCommand(UUID.randomUUID(),UUID.randomUUID(),null,"STUDENTSHIP_TERMINATION","private-evidence-reference",true);
        assertThat(report.toString()).doesNotContain("private-evidence-reference");
        assertThat(proof.toString()).doesNotContain("private-evidence-reference");
    }
}
