package com.unidocs.auth.registration.student;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.core.sync.RequestBody;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
@ExtendWith(MockitoExtension.class)
class S3EvidenceStorageTests {
    @Mock S3Client client;
    @Test void storesEvidenceInPrivateBucketWithoutPublishingAnAclOrUsingUploadedFilename() {
        S3EvidenceStorage storage=new S3EvidenceStorage(client,"student-evidence");
        StudentEvidence evidence=new StudentEvidence("%PDF-1.7 test".getBytes(),"application/pdf");storage.put("admissions/generated-id",evidence);
        ArgumentCaptor<PutObjectRequest> request=ArgumentCaptor.forClass(PutObjectRequest.class);
        verify(client).putObject(request.capture(),any(RequestBody.class));
        assertThat(request.getValue().bucket()).isEqualTo("student-evidence");assertThat(request.getValue().key()).isEqualTo("admissions/generated-id");
        assertThat(request.getValue().contentType()).isEqualTo("application/pdf");assertThat(request.getValue().aclAsString()).isNull();
    }
}
