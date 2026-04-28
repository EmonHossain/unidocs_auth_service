package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.PermissionsServiceGrpc;
import com.authzed.grpcutil.BearerToken;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import java.time.Clock;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration(proxyBeanMethods = false)
@org.springframework.boot.autoconfigure.condition.ConditionalOnExpression("${auth.spicedb.projection.enabled:false} or ${auth.spicedb.individual.publisher-enabled:false}")
@EnableConfigurationProperties(SpiceDbOrganizationSyncProperties.class)
@EnableScheduling
public class SpiceDbOrganizationSyncConfiguration {
    @Bean(destroyMethod = "shutdownNow")
    ManagedChannel spiceDbOrganizationSyncChannel(SpiceDbOrganizationSyncProperties properties, Environment environment) {
        if (properties.presharedKey().isBlank()) throw new IllegalStateException("IAM projection requires its separate writer credential.");
        if (properties.plaintext() && environment.matchesProfiles("prod")) {
            throw new IllegalStateException("Plaintext SpiceDB organization-sync transport is forbidden in the production profile.");
        }
        ManagedChannelBuilder<?> builder = ManagedChannelBuilder.forTarget(properties.endpoint());
        if (properties.plaintext()) builder.usePlaintext();
        else builder.useTransportSecurity();
        return builder.build();
    }

    @Bean
    SpiceDbRelationshipWriter spiceDbRelationshipWriter(ManagedChannel spiceDbOrganizationSyncChannel,
            SpiceDbOrganizationSyncProperties properties) {
        return new SpiceDbRelationshipWriter(PermissionsServiceGrpc.newBlockingStub(spiceDbOrganizationSyncChannel)
                .withCallCredentials(new BearerToken(properties.presharedKey())),
                properties.deadlineMillis(), properties.maxBatchSize());
    }

    @Bean
    @ConditionalOnProperty(prefix = "auth.spicedb.projection", name = "enabled", havingValue = "true")
    SpiceDbOrganizationSyncService spiceDbOrganizationSyncService(
            org.springframework.jdbc.core.JdbcTemplate jdbc, org.springframework.transaction.PlatformTransactionManager manager,
            SpiceDbOrganizationSyncProperties properties) {
        return new SpiceDbOrganizationSyncService(jdbc, manager, properties);
    }

    @Bean
    @ConditionalOnProperty(prefix = "auth.spicedb.projection", name = "enabled", havingValue = "true")
    SpiceDbOrganizationSyncWorker spiceDbOrganizationSyncWorker(
            SpiceDbOrganizationSyncService syncService, SpiceDbRelationshipWriter relationshipWriter,
            Clock clock, io.micrometer.core.instrument.MeterRegistry metrics) {
        return new SpiceDbOrganizationSyncWorker(syncService, relationshipWriter, clock, metrics);
    }
}
