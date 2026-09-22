package com.unidocs.auth.registration.student;
import java.net.URI;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.TestcontainersConfiguration;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import static org.assertj.core.api.Assertions.*;
class S3EvidenceIntegrationTests {
    private static final GenericContainer<?> STORAGE=start();
    private static GenericContainer<?> start() {
        GenericContainer<?> container=new GenericContainer<>("rustfs/rustfs:1.0.1")
            .withEnv("RUSTFS_ACCESS_KEY","test-admission-storage").withEnv("RUSTFS_SECRET_KEY","test-only-evidence-password")
            .withEnv("RUSTFS_VOLUMES","/data").withEnv("RUSTFS_CONSOLE_ENABLE","false").withCommand("rustfs").withExposedPorts(9000).waitingFor(Wait.forHttp("/health").forPort(9000))
            .withStartupTimeout(java.time.Duration.ofMinutes(5)).withReuse(TestcontainersConfiguration.getInstance().environmentSupportsReuse());
        container.start();return container; // Leave reusable storage running locally.
    }
    @Test void privateObjectCanBeStoredReadAndIdempotentlyDeletedThroughRealS3() throws Exception {
        URI endpoint=URI.create("http://"+STORAGE.getHost()+":"+STORAGE.getMappedPort(9000));
        try(S3Client client=S3Client.builder().endpointOverride(endpoint).region(Region.US_EAST_1).httpClientBuilder(UrlConnectionHttpClient.builder())
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test-admission-storage","test-only-evidence-password")))
                .serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(true).build()).build()) {
            String bucket="admission-"+UUID.randomUUID();client.createBucket(CreateBucketRequest.builder().bucket(bucket).build());
            S3EvidenceStorage store=new S3EvidenceStorage(client,bucket);String key="admissions/"+UUID.randomUUID();
            StudentEvidence evidence=new StudentEvidence("%PDF-1.7 private test".getBytes(),"application/pdf");store.put(key,evidence);
            assertThat(store.get(key)).isEqualTo(evidence.bytes());
            java.net.http.HttpResponse<Void> anonymous=java.net.http.HttpClient.newHttpClient().send(java.net.http.HttpRequest.newBuilder(endpoint.resolve("/"+bucket+"/"+key)).GET().build(),java.net.http.HttpResponse.BodyHandlers.discarding());
            assertThat(anonymous.statusCode()).isEqualTo(403);
            store.delete(key);store.delete(key);assertThatThrownBy(()->store.get(key)).isInstanceOf(NoSuchKeyException.class);
            client.deleteBucket(DeleteBucketRequest.builder().bucket(bucket).build());
        }
    }
}
