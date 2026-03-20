package com.unidocs.auth.registration.application;

import org.springframework.http.HttpStatus;

public class RegistrationException extends RuntimeException {
    private final HttpStatus status;

    public RegistrationException(HttpStatus status) {
        super("Registration request could not be processed.");
        this.status = status;
    }

    public HttpStatus status() { return status; }
}
