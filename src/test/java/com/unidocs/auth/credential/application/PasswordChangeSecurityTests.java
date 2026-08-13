package com.unidocs.auth.credential.application;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import com.unidocs.auth.session.persistence.SessionRepository;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;
class PasswordChangeSecurityTests {
    @Test void rejectsRevocationWithoutTheCredentialTransaction() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        SessionRepository sessions = mock(SessionRepository.class);
        PasswordChangeSecurity security = new PasswordChangeSecurity(jdbc, sessions);
        assertThatThrownBy(() -> security.revoke(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), Instant.now()))
                .isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(jdbc, sessions);
    }
}
