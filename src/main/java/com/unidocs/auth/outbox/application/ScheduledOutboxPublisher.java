package com.unidocs.auth.outbox.application;

import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

public class ScheduledOutboxPublisher {
    private static final Logger LOGGER = LoggerFactory.getLogger(ScheduledOutboxPublisher.class);
    private final OutboxPublisher publisher;
    private final MeterRegistry metrics;

    public ScheduledOutboxPublisher(OutboxPublisher publisher, MeterRegistry metrics) {
        this.publisher = publisher;
        this.metrics = metrics;
    }

    @Scheduled(fixedDelayString = "${auth.outbox.poll-interval:5000}", initialDelayString = "${auth.outbox.poll-interval:5000}")
    public void poll() {
        try {
            publisher.publishBatch();
        } catch (RuntimeException failure) {
            metrics.counter("outbox.poll.failures").increment();
            LOGGER.warn("Outbox publisher cycle failed; failureType={}", failure.getClass().getSimpleName());
        }
    }
}
