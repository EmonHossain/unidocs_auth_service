package com.unidocs.auth.registration.student;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;
public record StudentEvidence(byte[] bytes,String contentType) {
    public static final int MAX_BYTES=5*1024*1024;
    public StudentEvidence {
        if(bytes==null||bytes.length<8||bytes.length>MAX_BYTES)throw new IllegalArgumentException("Invalid evidence size.");
        boolean pdf=Arrays.equals(Arrays.copyOf(bytes,5),"%PDF-".getBytes(StandardCharsets.US_ASCII));
        boolean png=Arrays.equals(Arrays.copyOf(bytes,8),new byte[]{(byte)137,80,78,71,13,10,26,10});
        boolean jpeg=bytes[0]==(byte)255&&bytes[1]==(byte)216&&bytes[2]==(byte)255;
        if(!(pdf&&"application/pdf".equals(contentType)||png&&"image/png".equals(contentType)||jpeg&&"image/jpeg".equals(contentType)))throw new IllegalArgumentException("Unsupported evidence format.");
        bytes=bytes.clone();
    }
    @Override public byte[] bytes() { return bytes.clone(); }
    @Override public String toString() { return "StudentEvidence[REDACTED]"; }
}
