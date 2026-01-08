package com.unidocs.auth.credential.application;
import com.unidocs.auth.account.domain.AccountChallenge.Method;
public interface AccountProofVerifier {
    boolean supports(Method method);
    boolean verify(Method method, String secret, String storedHash);
}
