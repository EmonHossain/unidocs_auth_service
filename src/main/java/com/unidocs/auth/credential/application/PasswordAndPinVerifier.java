package com.unidocs.auth.credential.application;
import org.springframework.stereotype.Component;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.unidocs.auth.account.domain.AccountChallenge.Method;
@Component
public class PasswordAndPinVerifier implements AccountProofVerifier {
    private final PasswordEncoder encoder;
    public PasswordAndPinVerifier(PasswordEncoder encoder) { this.encoder = encoder; }
    public boolean supports(Method method) { return method == Method.PASSWORD || method == Method.PIN; }
    public boolean verify(Method method, String secret, String storedHash) {
        return supports(method) && secret != null && !secret.isBlank() && secret.length() <= 128
                && encoder.matches(secret, storedHash);
    }
}
