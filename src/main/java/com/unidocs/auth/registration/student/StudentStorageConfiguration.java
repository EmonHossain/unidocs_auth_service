package com.unidocs.auth.registration.student;
import java.net.URI;
import java.time.Duration;
import org.springframework.context.annotation.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
@Configuration(proxyBeanMethods=false)
@ConditionalOnProperty(name="registration.student.storage.enabled",havingValue="true")
public class StudentStorageConfiguration {
    @Bean(destroyMethod="close")
    S3Client studentEvidenceClient(@Value("${registration.student.storage.endpoint}") URI endpoint,
            @Value("${registration.student.storage.access-key}") String key,@Value("${registration.student.storage.secret-key}") String secret) {
        return S3Client.builder().endpointOverride(endpoint).region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(key,secret)))
                .serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(true).build())
                .httpClientBuilder(UrlConnectionHttpClient.builder().connectionTimeout(Duration.ofSeconds(3)).socketTimeout(Duration.ofSeconds(10)))
                .overrideConfiguration(ClientOverrideConfiguration.builder().apiCallTimeout(Duration.ofSeconds(15)).build()).build();
    }
    @Bean
    EvidenceStorage studentEvidenceStorage(S3Client client,@Value("${registration.student.storage.bucket:student-evidence}") String bucket,
            @Value("${registration.student.storage.create-bucket:false}") boolean create) {
        if(create) {
            try { client.createBucket(CreateBucketRequest.builder().bucket(bucket).build()); }
            catch(BucketAlreadyOwnedByYouException existing) { /* local restarts preserve the private bucket */ }
        }
        return new S3EvidenceStorage(client,bucket);
    }
}
