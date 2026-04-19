package com.unidocs.auth.security.ratelimit;
public class RateLimitException extends RuntimeException {
    private final long retryAfterSeconds;
    public RateLimitException(long retryAfterSeconds) {
        super("Too many requests.");
        this.retryAfterSeconds = retryAfterSeconds;
    }
    public long retryAfterSeconds() { return retryAfterSeconds; }
}
