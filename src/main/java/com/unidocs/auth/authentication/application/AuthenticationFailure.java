package com.unidocs.auth.authentication.application;

public final class AuthenticationFailure extends RuntimeException {
    public AuthenticationFailure() { super("Authentication failed."); }
}
