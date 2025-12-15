package com.unidocs.auth.authorization.application;

import java.util.Optional;
import com.unidocs.auth.authorization.domain.OperationPolicySnapshot;
import com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Internal catalog reads only. The caller must establish the selected account's category independently. */
@Service
@Transactional(readOnly = true)
public class OperationPolicyCatalogService {
    private final OperationPolicyCatalogRepository repository;

    public OperationPolicyCatalogService(OperationPolicyCatalogRepository repository) {
        this.repository = repository;
    }

    public Optional<OperationPolicySnapshot> load(String serviceId, String operationKey, String categoryKey) {
        validateKey(serviceId, 64);
        validateKey(operationKey, 128);
        if (!"INDIVIDUAL".equals(categoryKey) && !"ORGANIZATION".equals(categoryKey) && !"STUDENT".equals(categoryKey)) {
            throw new IllegalArgumentException("Unknown stakeholder context");
        }
        return repository.findCurrent(serviceId, operationKey, categoryKey);
    }

    private static void validateKey(String key, int maximumLength) {
        if (key == null || key.length() > maximumLength || !key.matches("[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")) {
            throw new IllegalArgumentException("Invalid service-owned catalog key");
        }
    }
}
