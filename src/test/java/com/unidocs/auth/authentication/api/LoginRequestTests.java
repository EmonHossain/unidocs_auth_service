package com.unidocs.auth.authentication.api;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
class LoginRequestTests {
    @Test void canonicalizesEmailAndPreservesPassword() {
        LoginRequest request=new LoginRequest("\u2002 USER@EXAMPLE.COM \u2002"," password ");
        assertThat(request.email()).isEqualTo("user@example.com");
        assertThat(request.password()).isEqualTo(" password ");
        assertThat(request.toString()).doesNotContain("user@example.com","password");
    }
    @Test void usesRootLocaleAndAllowsNullForValidation() {
        Locale previous=Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            assertThat(new LoginRequest("IDENTITY@EXAMPLE.COM","secret").email()).isEqualTo("identity@example.com");
            assertThat(new LoginRequest(null,"secret").email()).isNull();
        } finally { Locale.setDefault(previous); }
    }
}
