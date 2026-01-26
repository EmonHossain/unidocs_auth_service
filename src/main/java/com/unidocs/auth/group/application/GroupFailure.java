package com.unidocs.auth.group.application;

import org.springframework.http.HttpStatus;

public final class GroupFailure extends RuntimeException {
    private final HttpStatus status;
    public GroupFailure(HttpStatus status) { super("Group operation failed."); this.status = status; }
    public HttpStatus status() { return status; }
}
