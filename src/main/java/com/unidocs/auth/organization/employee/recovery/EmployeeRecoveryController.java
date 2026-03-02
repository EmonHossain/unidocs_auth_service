package com.unidocs.auth.organization.employee.recovery;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
import java.util.List;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

@Tag(name = "Employee password recovery", description = "Administrator-assisted employee identity recovery.")
@RestController
@RequestMapping("${api.version.base-path}")
public class EmployeeRecoveryController {
    private final EmployeeRecoveryService service;
    public EmployeeRecoveryController(EmployeeRecoveryService service) { this.service=service; }
    @Operation(summary = "Request employee password recovery", description = "Registers a recovery request without disclosing whether the username exists.")
    @ApiResponse(responseCode = "202", description = "Recovery request accepted without disclosing username existence.")
    @PostMapping("/auth/employee-forgot-password")
    ResponseEntity<Void> request(@Valid @RequestBody EmployeeRecoveryRequests.Forgot request) { service.request(request);return ResponseEntity.accepted().header("Cache-Control","no-store").build(); }
    @Operation(summary = "List employee recovery requests", description = "An authorized organization administrator lists outstanding recovery requests using cursor pagination.")
    @GetMapping("/organizations/{org}/password-recovery-requests")
    @org.springframework.security.access.prepost.PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    ResponseEntity<List<EmployeeRecoveryRequests.View>> list(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID org,@RequestParam UUID adminAccountId,
            @RequestParam(required=false) UUID after,@RequestParam(defaultValue="20") int limit) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(service.list(sid(jwt),subject(jwt),org,adminAccountId,after,limit));
    }
    @Operation(summary = "Issue an employee recovery PIN", description = "An authorized administrator confirms identity verification and supplies password proof to issue a recovery PIN.")
    @PostMapping("/organizations/{org}/password-recovery-requests/{requestId}/reset")
    @org.springframework.security.access.prepost.PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    ResponseEntity<EmployeeRecoveryRequests.Pin> issue(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID org,@PathVariable UUID requestId,@Valid @RequestBody EmployeeRecoveryRequests.Issue request) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(service.issue(sid(jwt),subject(jwt),org,requestId,request));
    }
    @Operation(summary = "Reset an employee password", description = "Verifies the recovery PIN and sets a new password subject to current membership, credential version and attempt limits.")
    @ApiResponse(responseCode = "204", description = "Employee password reset completed.")
    @PostMapping("/auth/employee-reset-password")
    ResponseEntity<Void> reset(@Valid @RequestBody EmployeeRecoveryRequests.Reset request) { service.reset(request);return ResponseEntity.noContent().header("Cache-Control","no-store").build(); }
    private static UUID sid(Jwt jwt) { return UUID.fromString(jwt.getClaimAsString("sid")); }
    private static UUID subject(Jwt jwt) { return UUID.fromString(jwt.getSubject()); }
}
