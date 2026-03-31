package com.unidocs.auth.registration.student;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
import java.io.IOException;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import com.unidocs.auth.organization.application.OrganizationFailure;
@Tag(name = "Student admissions", description = "Institute admission, mailbox verification and evidence review.")
@RestController
@RequestMapping("${api.version.base-path}")
@org.springframework.security.access.prepost.PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
public class StudentAdmissionController {
    private final StudentAdmissionService admissions;
    public StudentAdmissionController(StudentAdmissionService admissions) { this.admissions=admissions; }
    @Operation(summary = "Apply for student admission", description = "Submits an institute email or optional JPEG, PNG or PDF evidence up to 5 MiB. Both admission paths require mailbox verification.")
    @ApiResponse(responseCode = "201", description = "Student admission submitted; mailbox verification is required.", useReturnTypeSchema = true)
    @PostMapping(value="/institutes/{org}/student-admissions",consumes=MediaType.MULTIPART_FORM_DATA_VALUE)
    ResponseEntity<StudentRequests.View> apply(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID org,
            @RequestPart("application") @Valid StudentRequests.Apply command,@RequestPart(value="evidence",required=false) MultipartFile file) throws IOException {
        StudentEvidence evidence=null;
        if(file!=null) {
            if(file.getSize()>StudentEvidence.MAX_BYTES)throw new OrganizationFailure(HttpStatus.PAYLOAD_TOO_LARGE);
            try { evidence=new StudentEvidence(file.getBytes(),file.getContentType()); } catch(IllegalArgumentException invalid) { throw new OrganizationFailure(HttpStatus.BAD_REQUEST); }
        }
        return ResponseEntity.status(201).header("Cache-Control","no-store").body(admissions.apply(sid(jwt),subject(jwt),org,command,evidence));
    }
    @Operation(summary = "Verify an admission email", description = "Verifies the mailbox code. Institute-domain admission provisions an account; evidence admission proceeds to curator review.")
    @PostMapping("/institutes/{org}/student-admissions/{id}/verify")
    ResponseEntity<StudentRequests.View> verify(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID org,@PathVariable UUID id,@Valid @RequestBody StudentRequests.Verify command) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(admissions.verify(sid(jwt),subject(jwt),org,id,command));
    }
    @Operation(summary = "Get a student admission", description = "Returns admission status when the selected account is authorized to view it.")
    @GetMapping("/institutes/{org}/student-admissions/{id}")
    ResponseEntity<StudentRequests.View> get(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID org,@PathVariable UUID id,@RequestParam UUID accountId) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(admissions.get(sid(jwt),subject(jwt),org,id,accountId));
    }
    @Operation(summary = "Review admission evidence", description = "An institute curator approves or rejects verified evidence. Approval does not grant course enrollment.")
    @PostMapping("/institutes/{org}/student-admissions/{id}/review")
    ResponseEntity<StudentRequests.View> review(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID org,@PathVariable UUID id,@Valid @RequestBody StudentRequests.Review command) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(admissions.review(sid(jwt),subject(jwt),org,id,command));
    }
    @Operation(summary = "List student admissions", description = "Returns admissions visible to the selected account using cursor pagination.")
    @GetMapping("/institutes/{org}/student-admissions")
    ResponseEntity<StudentAdmissionService.Page> list(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID org,@RequestParam UUID accountId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") int limit) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(admissions.list(sid(jwt),subject(jwt),org,accountId,after,limit));
    }
    @Operation(summary = "Download admission evidence", description = "Returns the uploaded evidence as an attachment after checking institute-scoped access.")
    @GetMapping("/institutes/{org}/student-admissions/{id}/evidence")
    ResponseEntity<byte[]> evidence(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID org,@PathVariable UUID id,@RequestParam UUID accountId) {
        StudentRequests.Evidence evidence=admissions.evidence(sid(jwt),subject(jwt),org,id,accountId);
        return ResponseEntity.ok().header("Cache-Control","no-store").header("X-Content-Type-Options","nosniff")
                .header("Content-Disposition","attachment; filename=student-evidence").contentType(MediaType.parseMediaType(evidence.contentType())).body(evidence.bytes());
    }
    @Operation(summary = "Configure a student email domain", description = "An institute administrator adds an explicitly trusted student email domain.")
    @ApiResponse(responseCode = "204", description = "Student email domain configured.")
    @PutMapping("/institutes/{org}/student-email-domains")
    ResponseEntity<Void> domain(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID org,@Valid @RequestBody StudentRequests.Domain command) {
        admissions.domain(sid(jwt),subject(jwt),org,command);return ResponseEntity.noContent().header("Cache-Control","no-store").build();
    }
    @Operation(summary = "Manage an institute curator", description = "An institute administrator enables or disables curator assignment for a membership.")
    @ApiResponse(responseCode = "204", description = "Curator assignment updated.")
    @PutMapping("/institutes/{org}/curators")
    ResponseEntity<Void> curator(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID org,@Valid @RequestBody StudentRequests.Curator command) {
        admissions.assignCurator(sid(jwt),subject(jwt),org,command);return ResponseEntity.noContent().header("Cache-Control","no-store").build();
    }
    private static UUID sid(Jwt jwt) { return UUID.fromString(jwt.getClaimAsString("sid")); }
    private static UUID subject(Jwt jwt) { return UUID.fromString(jwt.getSubject()); }
}
