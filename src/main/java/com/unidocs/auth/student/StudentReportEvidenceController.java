package com.unidocs.auth.student;

import java.io.IOException;
import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import com.unidocs.auth.registration.student.StudentEvidence;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("${api.version.base-path}/institutes/{organization}/workspace")
@PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
public class StudentReportEvidenceController {
    public record Upload(@NotNull UUID accountId,@NotNull UUID courseId,UUID reportId,@NotNull UUID evidenceId) { }
    private final StudentReportEvidenceService service;
    public StudentReportEvidenceController(StudentReportEvidenceService service) { this.service=service; }
    @PostMapping(value="/report-evidence",consumes=MediaType.MULTIPART_FORM_DATA_VALUE)
    public UUID upload(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@Valid @RequestPart("metadata") Upload request,@RequestPart("file") MultipartFile file) throws IOException {
        if(file.getSize()>StudentEvidence.MAX_BYTES) throw StudentWorkspaceService.bad();
        StudentEvidence evidence;
        try { evidence=new StudentEvidence(file.getBytes(),file.getContentType()); }
        catch(IllegalArgumentException invalid) { throw StudentWorkspaceService.bad(); }
        return service.upload(jwt,organization,request.accountId(),request.courseId(),request.reportId(),request.evidenceId(),evidence);
    }
    @GetMapping("/reports/{report}/evidence/{evidence}")
    public ResponseEntity<byte[]> download(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@PathVariable UUID report,@PathVariable UUID evidence,@RequestParam UUID accountId) {
        StudentReportEvidenceService.Download result=service.download(jwt,organization,accountId,report,evidence);
        return ResponseEntity.ok().header(HttpHeaders.CACHE_CONTROL,"no-store").header("X-Content-Type-Options","nosniff")
                .header(HttpHeaders.CONTENT_DISPOSITION,"attachment; filename=student-evidence").contentType(MediaType.parseMediaType(result.contentType())).body(result.bytes());
    }
}
