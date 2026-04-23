package com.unidocs.auth.security.ratelimit;
public class RateLimitUnavailableException extends RuntimeException {
    public RateLimitUnavailableException() { super("Request admission is unavailable."); }
}
