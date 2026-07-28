package com.unidocs.auth.authorization;

import com.unidocs.auth.authorization.application.OrganizationInvalidationListener;
import com.unidocs.auth.authorization.application.OrganizationSnapshotStore;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OrganizationInvalidationListenerTests {
    @Mock OrganizationSnapshotStore snapshots;
    private final SimpleMeterRegistry metrics = new SimpleMeterRegistry();

    @Test
    void validOrganizationEventDelegatesVersionedRepeatableInvalidation() {
        UUID id = UUID.randomUUID();
        ConsumerRecord<String,String> event = event(id, "2", "ORGANIZATION_MEMBERSHIP_ACTIVATED");
        OrganizationInvalidationListener listener = new OrganizationInvalidationListener(snapshots, metrics);
        listener.invalidate(event);
        listener.invalidate(event);
        verify(snapshots, times(2)).invalidate(id, 2);
    }

    @Test
    void malformedVersionAndMissingHeadersAreSkippedWithoutLoggingRecordData() {
        OrganizationInvalidationListener listener = new OrganizationInvalidationListener(snapshots, metrics);
        listener.invalidate(event(UUID.randomUUID(), "-1", "ORGANIZATION_CREATED"));
        listener.invalidate(event(UUID.randomUUID(), "not-a-version", "ORGANIZATION_CREATED"));
        listener.invalidate(new ConsumerRecord<>("topic", 0, 0, "key", "sensitive-payload"));
        ConsumerRecord<String,String> nullHeader = event(UUID.randomUUID(), "1", "ORGANIZATION_CREATED");
        nullHeader.headers().remove("aggregateVersion").add("aggregateVersion", (byte[]) null);
        listener.invalidate(nullHeader);
        verifyNoInteractions(snapshots);
        assertThat(metrics.get("authorization.invalidation").tag("outcome", "invalid_event").counter().count()).isEqualTo(4);
    }

    @Test
    void lifecycleEventsInvalidateCachesWithVersionedMockitoCalls() {
        OrganizationInvalidationListener listener=new OrganizationInvalidationListener(snapshots,metrics);
        UUID id=UUID.randomUUID();
        for(String type:java.util.List.of("ORGANIZATION_MEMBER_REMOVED","ORGANIZATION_MEMBER_BLACKLISTED",
                "ORGANIZATION_MEMBER_RESTORED","ORGANIZATION_ACCOUNT_PURGED","ORGANIZATION_ACCOUNT_AVAILABILITY_CHANGED","ORGANIZATION_GROUP_MEMBERSHIP_CHANGED"))
            listener.invalidate(event(id,"12",type));
        verify(snapshots,times(6)).invalidate(id,12);
    }
    @Test
    void unrelatedDomainEventsDoNotInvalidateOrganizationPermissionState() {
        OrganizationInvalidationListener listener = new OrganizationInvalidationListener(snapshots, metrics);
        listener.invalidate(event(UUID.randomUUID(), "5", "ORGANIZATION_INVITATION_CHANGED"));
        verifyNoInteractions(snapshots);
    }
    @Test
    void professionalEventsInvalidateEveryInstancesOrganizationProjection() {
        OrganizationInvalidationListener listener=new OrganizationInvalidationListener(snapshots,metrics);
        UUID id=UUID.randomUUID();
        for(String type:java.util.List.of("PROFESSIONAL_RESPONSIBILITY_CHANGED","PROFESSIONAL_ACCESS_CHANGED","PROFESSIONAL_ACCOUNT_RECONCILED")) {
            listener.invalidate(event(id,"20",type));
        }
        verify(snapshots,times(3)).invalidate(id,20);
    }

    private static ConsumerRecord<String,String> event(UUID id, String version, String type) {
        ConsumerRecord<String,String> event = new ConsumerRecord<>("topic", 0, 0, "key", "payload");
        event.headers().add("aggregateType", "ORGANIZATION".getBytes(StandardCharsets.UTF_8));
        event.headers().add("eventType", type.getBytes(StandardCharsets.UTF_8));
        event.headers().add("aggregateId", id.toString().getBytes(StandardCharsets.UTF_8));
        event.headers().add("aggregateVersion", version.getBytes(StandardCharsets.UTF_8));
        return event;
    }
}
