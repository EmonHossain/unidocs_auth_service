package com.unidocs.auth.organization.application;
import org.springframework.http.HttpStatus;
public final class OrganizationFailure extends RuntimeException {
    private final HttpStatus status;
    public OrganizationFailure(HttpStatus status) { super("Organization operation failed."); this.status=status; }
    public HttpStatus status() { return status; }
}
