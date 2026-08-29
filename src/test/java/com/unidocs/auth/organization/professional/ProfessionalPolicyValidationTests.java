package com.unidocs.auth.organization.professional;

import java.time.Instant;
import java.util.UUID;
import jakarta.validation.Validation;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class ProfessionalPolicyValidationTests {
    @Test void responsibilityRequiresActorTargetRoleAndPositiveVersion() {
        try(ValidatorFactory factory=Validation.buildDefaultValidatorFactory()) {
            ProfessionalPolicyService.Responsibility missing=new ProfessionalPolicyService.Responsibility(null,null,null,null,true,null,0);
            assertThat(factory.getValidator().validate(missing)).hasSize(4);
            ProfessionalPolicyService.Responsibility valid=new ProfessionalPolicyService.Responsibility(UUID.randomUUID(),UUID.randomUUID(),null,UUID.randomUUID(),true,Instant.now().plusSeconds(60),1);
            assertThat(factory.getValidator().validate(valid)).isEmpty();
        }
    }
    @Test void organizationWideRestrictionsAllowNullTargetButRequireOperationAndVersion() {
        try(ValidatorFactory factory=Validation.buildDefaultValidatorFactory()) {
            assertThat(factory.getValidator().validate(new ProfessionalPolicyService.Restriction(UUID.randomUUID(),null,null,UUID.randomUUID(),true,null,1))).isEmpty();
            assertThat(factory.getValidator().validate(new ProfessionalPolicyService.Restriction(null,null,null,null,true,null,-1))).hasSize(3);
        }
    }
}
