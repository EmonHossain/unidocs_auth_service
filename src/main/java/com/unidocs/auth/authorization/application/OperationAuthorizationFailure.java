package com.unidocs.auth.authorization.application;

import org.springframework.http.HttpStatus;

public final class OperationAuthorizationFailure extends RuntimeException {
    private final HttpStatus status;
    private final String reasonCode;

    public OperationAuthorizationFailure(HttpStatus status, String reasonCode) {
        super("Operation authorization failed");
        this.status = status;
        this.reasonCode = reasonCode;
    }

    public HttpStatus status() { return status; }
    public String reasonCode() { return reasonCode; }
}
