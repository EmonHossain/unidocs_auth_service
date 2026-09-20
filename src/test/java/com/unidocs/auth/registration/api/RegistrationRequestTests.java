package com.unidocs.auth.registration.api;

import java.util.Locale;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import static org.assertj.core.api.Assertions.assertThat;

class RegistrationRequestTests {
    private static ValidatorFactory validatorFactory;
    private static Validator validator;

    @BeforeAll
    static void initializeValidator() {
        validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @AfterAll
    static void closeValidator() {
        validatorFactory.close();
    }

    @Test
    void validatesNormalizedEmailWhilePreservingDisplayNameAndPasswordExactly() {
        String displayName = "  User Name  ";
        String password = "  passWord-with-spaces  ";
        RegistrationRequest request = new RegistrationRequest(displayName,
                " \t UsEr@Example.COM \r\n", password);

        assertThat(request.email()).isEqualTo("user@example.com");
        assertThat(request.displayName()).isEqualTo(displayName);
        assertThat(request.password()).isEqualTo(password);
        assertThat(validator.validate(request)).isEmpty();
    }

    @Test
    void stripsUnicodeWhitespaceAtTheEmailBoundary() {
        RegistrationRequest request = new RegistrationRequest("User",
                "\u2003USER@EXAMPLE.COM\u2003", "password-long-enough");

        assertThat(request.email()).isEqualTo("user@example.com");
        assertThat(validator.validate(request)).isEmpty();
    }

    @Test
    @ResourceLock("default-locale")
    void emailNormalizationDoesNotDependOnDefaultLocale() {
        Locale originalLocale = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            RegistrationRequest request = new RegistrationRequest("User",
                    " IDENTIFIER@EXAMPLE.COM ", "password-long-enough");

            assertThat(request.email()).isEqualTo("identifier@example.com");
            assertThat(validator.validate(request)).isEmpty();
        } finally {
            Locale.setDefault(originalLocale);
        }
    }

    @Test
    void missingBlankAndMalformedEmailsRemainInvalid() {
        for (String email : new String[] { null, "", " \t ", "not-an-email", "user @example.com" }) {
            RegistrationRequest request = new RegistrationRequest("User", email, "password-long-enough");

            assertThat(validator.validate(request))
                    .anyMatch(violation -> violation.getPropertyPath().toString().equals("email"));
        }
    }

    @Test
    void existingInputBoundsStillApplyAfterNormalization() {
        RegistrationRequest oversizedEmail = new RegistrationRequest("User",
                "a".repeat(250) + "@example.com", "password-long-enough");
        assertThat(validator.validate(oversizedEmail))
                .anyMatch(violation -> violation.getPropertyPath().toString().equals("email"));

        for (String password : new String[] { null, " ".repeat(12), "a".repeat(11), "a".repeat(129) }) {
            RegistrationRequest request = new RegistrationRequest("User", "user@example.com", password);
            assertThat(validator.validate(request))
                    .anyMatch(violation -> violation.getPropertyPath().toString().equals("password"));
        }
        for (String displayName : new String[] { null, " ", "a".repeat(101) }) {
            RegistrationRequest request = new RegistrationRequest(displayName, "user@example.com",
                    "password-long-enough");
            assertThat(validator.validate(request))
                    .anyMatch(violation -> violation.getPropertyPath().toString().equals("displayName"));
        }
    }

    @Test
    void toStringDoesNotExposeAnyRegistrationFields() {
        RegistrationRequest request = new RegistrationRequest("private-name", "private-email@example.com",
                "private-password");

        assertThat(request.toString()).isEqualTo("RegistrationRequest[redacted]");
    }
}
