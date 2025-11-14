package com.unidocs.auth.account.lifecycle;

import java.time.Instant;
import java.time.ZoneOffset;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class RetentionPolicy {
    private final int months;
    public RetentionPolicy(@Value("${auth.account-lifecycle.retention-months:3}") int months) {
        if (months != 3 && months != 12) throw new IllegalArgumentException("Retention must be 3 or 12 months.");
        this.months = months;
    }
    public Instant deadline(Instant now) { return now.atZone(ZoneOffset.UTC).plusMonths(months).toInstant(); }
    public boolean recoverable(String status, Instant deadline, Instant now) {
        return "SOFT_DELETED".equals(status) && deadline != null && now.isBefore(deadline);
    }
}
