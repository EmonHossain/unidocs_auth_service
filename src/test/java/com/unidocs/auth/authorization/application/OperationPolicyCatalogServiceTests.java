package com.unidocs.auth.authorization.application;

import java.util.Optional;
import com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.DataAccessResourceFailureException;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class OperationPolicyCatalogServiceTests {
    private final OperationPolicyCatalogRepository repository = mock(OperationPolicyCatalogRepository.class);
    private final OperationPolicyCatalogService service = new OperationPolicyCatalogService(repository);

    @Test
    void missingCatalogStateHasNoFallback() {
        when(repository.findCurrent("document-service", "file.share", "INDIVIDUAL")).thenReturn(Optional.empty());
        assertThat(service.load("document-service", "file.share", "INDIVIDUAL")).isEmpty();
        verify(repository).findCurrent("document-service", "file.share", "INDIVIDUAL");
    }

    @Test
    void databaseOutagePropagatesWithoutCachedAllow() {
        when(repository.findCurrent("document-service", "file.share", "INDIVIDUAL"))
                .thenThrow(new DataAccessResourceFailureException("unavailable"));
        assertThatThrownBy(() -> service.load("document-service", "file.share", "INDIVIDUAL"))
                .isInstanceOf(DataAccessResourceFailureException.class);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" file.share", "file.share ", "FILE_SHARE", "file/share", "file..share", "#{true}"})
    void rejectsMalformedKeysBeforePersistence(String invalid) {
        assertThatThrownBy(() -> service.load(invalid, "file.share", "INDIVIDUAL")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.load("document-service", invalid, "INDIVIDUAL")).isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(repository);
    }

    @Test
    void rejectsOversizedKeysAndUnknownContext() {
        assertThatThrownBy(() -> service.load("a".repeat(65), "file.share", "INDIVIDUAL"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.load("document-service", "a".repeat(129), "INDIVIDUAL"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.load("document-service", "file.share", "ADMIN"))
                .isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(repository);
    }
}
