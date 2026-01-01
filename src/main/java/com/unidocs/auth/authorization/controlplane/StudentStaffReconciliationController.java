package com.unidocs.auth.authorization.controlplane;

import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@io.swagger.v3.oas.annotations.Hidden
@RequestMapping("${api.version.base-path}/developer/institutes/{organization}/staff-reconciliations")
public class StudentStaffReconciliationController {
    public record Request(@NotNull DeveloperCatalogService.Proof proof,@NotNull StudentStaffReconciliationService.Command command) {
        @Override public String toString() { return "StudentStaffRequest[REDACTED]"; }
    }
    private final StudentStaffReconciliationService service;
    public StudentStaffReconciliationController(StudentStaffReconciliationService service) { this.service=service; }
    @PostMapping @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public StudentStaffReconciliationService.Result reconcile(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@Valid @RequestBody Request request) { return service.reconcile(jwt,request.proof(),organization,request.command()); }
}
