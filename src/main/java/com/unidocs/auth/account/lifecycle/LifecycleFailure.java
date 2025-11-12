package com.unidocs.auth.account.lifecycle;

import org.springframework.http.HttpStatus;

public class LifecycleFailure extends RuntimeException {
    private final HttpStatus status;
    private final String code;
    public LifecycleFailure(HttpStatus status, String code) { super(code); this.status=status; this.code=code; }
    public HttpStatus status() { return status; }
    public String code() { return code; }
    public static LifecycleFailure conflict(String code) { return new LifecycleFailure(HttpStatus.CONFLICT,code); }
    public static LifecycleFailure forbidden() { return new LifecycleFailure(HttpStatus.FORBIDDEN,"ACCOUNT_ACTION_FORBIDDEN"); }
}
