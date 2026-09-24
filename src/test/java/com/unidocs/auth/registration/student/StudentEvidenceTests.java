package com.unidocs.auth.registration.student;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
class StudentEvidenceTests {
    @Test void rejectsUnsupportedSpoofedAndOversizedDocuments() {
        assertThatThrownBy(()->new StudentEvidence("<html>evil</html>".getBytes(),"application/pdf")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->new StudentEvidence("%PDF-1.7 test".getBytes(),"image/jpeg")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->new StudentEvidence(new byte[StudentEvidence.MAX_BYTES+1],"application/pdf")).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void defensivelyCopiesAcceptedEvidence() {
        byte[] bytes="%PDF-1.7 test".getBytes();StudentEvidence evidence=new StudentEvidence(bytes,"application/pdf");bytes[0]=0;
        assertThat(evidence.bytes()[0]).isEqualTo((byte)'%');byte[] read=evidence.bytes();read[0]=0;assertThat(evidence.bytes()[0]).isEqualTo((byte)'%');
    }
}
