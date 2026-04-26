package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.PermissionsServiceGrpc;
import com.authzed.grpcutil.BearerToken;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import java.util.concurrent.TimeUnit;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SpiceDbProperties.class)
@ConditionalOnProperty(prefix = "auth.spicedb", name = "enabled", havingValue = "true")
public class SpiceDbClientConfiguration {
    @Bean(destroyMethod = "shutdownNow")
    ManagedChannel spiceDbChannel(SpiceDbProperties properties, Environment environment) {
        if (properties.plaintext() && environment.matchesProfiles("prod")) {
            throw new IllegalStateException("Plaintext SpiceDB transport is forbidden in the production profile.");
        }
        ManagedChannelBuilder<?> builder = ManagedChannelBuilder.forTarget(properties.endpoint());
        if (properties.plaintext()) {
            builder.usePlaintext();
        } else {
            builder.useTransportSecurity();
        }
        return builder.build();
    }

    @Bean
    SpiceDbPermissionClient spiceDbPermissionClient(ManagedChannel spiceDbChannel, SpiceDbProperties properties) {
        BearerToken credentials = new BearerToken(properties.presharedKey());
        return new SpiceDbPermissionClient(
                PermissionsServiceGrpc.newBlockingStub(spiceDbChannel).withCallCredentials(credentials),
                properties.deadlineMillis());
    }
}
