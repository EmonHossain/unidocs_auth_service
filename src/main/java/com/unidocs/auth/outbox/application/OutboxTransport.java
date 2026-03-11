package com.unidocs.auth.outbox.application;

import com.unidocs.auth.outbox.domain.ClaimedOutboxEvent;

public interface OutboxTransport {
    void publish(ClaimedOutboxEvent event) throws Exception;
}
