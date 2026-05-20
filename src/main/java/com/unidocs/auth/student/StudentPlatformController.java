package com.unidocs.auth.student;

import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import com.unidocs.auth.authorization.controlplane.DeveloperCatalogService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("${api.version.base-path}/developer/institutes/{organization}")
@PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
public class StudentPlatformController {
    public record Appointment(@NotNull DeveloperCatalogService.Proof proof,@Valid @NotNull StudentPlatformService.Appointment command) {
        @Override public String toString() { return "StudentAppointment[REDACTED]"; }
    }
    public record Evidence(@NotNull DeveloperCatalogService.Proof proof,@Valid @NotNull StudentPlatformService.ProofCommand command) {
        @Override public String toString() { return "StudentEvidence[REDACTED]"; }
    }
    public record Decision(@NotNull DeveloperCatalogService.Proof proof,@Valid @NotNull StudentPlatformService.Decision command) {
        @Override public String toString() { return "StudentDecision[REDACTED]"; }
    }
    private final StudentPlatformService service;
    public StudentPlatformController(StudentPlatformService service) { this.service=service; }
    @PostMapping("/student-admin")
    public StudentPlatformService.Result appoint(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@Valid @RequestBody Appointment request) { return service.appoint(jwt,request.proof(),organization,request.command()); }
    @PostMapping("/enforcement-proofs")
    public UUID proof(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@Valid @RequestBody Evidence request) { return service.verifyProof(jwt,request.proof(),organization,request.command()); }
    @PostMapping("/enforcement-decisions")
    public StudentPlatformService.Result enforce(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@Valid @RequestBody Decision request) { return service.enforce(jwt,request.proof(),organization,request.command()); }
}
