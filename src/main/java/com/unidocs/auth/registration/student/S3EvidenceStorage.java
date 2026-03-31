package com.unidocs.auth.registration.student;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.core.sync.RequestBody;
public class S3EvidenceStorage implements EvidenceStorage {
    private final S3Client client;
    private final String bucket;
    public S3EvidenceStorage(S3Client client,String bucket) { this.client=client;this.bucket=bucket; }
    public void put(String key,StudentEvidence evidence) {
        client.putObject(PutObjectRequest.builder().bucket(bucket).key(key).contentType(evidence.contentType()).build(),RequestBody.fromBytes(evidence.bytes()));
    }
    public byte[] get(String key) { return client.getObjectAsBytes(GetObjectRequest.builder().bucket(bucket).key(key).build()).asByteArray(); }
    public void delete(String key) { client.deleteObject(DeleteObjectRequest.builder().bucket(bucket).key(key).build()); }
}
