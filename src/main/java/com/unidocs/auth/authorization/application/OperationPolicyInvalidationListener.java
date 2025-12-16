package com.unidocs.auth.authorization.application;

import java.nio.charset.StandardCharsets;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.header.Header;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(prefix = "auth.authorization.cache", name = {"enabled", "listener-enabled"}, havingValue = "true")
public class OperationPolicyInvalidationListener {
    private final OperationPolicyCandidateCache cache;
    public OperationPolicyInvalidationListener(OperationPolicyCandidateCache cache) { this.cache = cache; }

    @KafkaListener(id = "operationPolicyInvalidation", topics = "${auth.outbox.topic}",
            groupId = "iam-policy-cache-${auth.authorization.cache.instance-id}",
            properties = {"auto.offset.reset=latest", "enable.auto.commit=false"})
    public void invalidate(ConsumerRecord<String, String> record) {
        try {
            if ("IAM_POLICY".equals(header(record, "aggregateType")) && "IAM_POLICY_CHANGED".equals(header(record, "eventType"))) {
                cache.invalidate(Long.parseLong(header(record, "aggregateVersion")));
            }
        } catch (IllegalArgumentException malformed) { /* Malformed hints never grant or lower a revision floor. */ }
    }
    private static String header(ConsumerRecord<String, String> record, String key) {
        Header header = record.headers().lastHeader(key);
        if (header == null || header.value() == null || header.value().length > 64) throw new IllegalArgumentException();
        return new String(header.value(), StandardCharsets.UTF_8);
    }
}
