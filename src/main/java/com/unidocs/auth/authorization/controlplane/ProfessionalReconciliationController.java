package com.unidocs.auth.authorization.controlplane;

import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@io.swagger.v3.oas.annotations.Hidden
@RequestMapping("${api.version.base-path}/developer")
public class ProfessionalReconciliationController {
    public record Request(UUID accountId,@NotBlank @Size(max=128) String password,
            @NotBlank @Size(max=64) String secondFactor,@NotNull UUID sourceAccountId,UUID targetAccountId,
            @Size(min=12,max=128) String newAccountPassword,@Size(max=100) String displayName,@Positive long expectedVersion,
            @Size(max=512) String reason) {
        public Request(UUID accountId,String password,String secondFactor,UUID sourceAccountId,UUID targetAccountId,
                String newAccountPassword,String displayName,long expectedVersion) {
            this(accountId,password,secondFactor,sourceAccountId,targetAccountId,newAccountPassword,displayName,expectedVersion,null);
        }
        @Override public String toString() { return "ProfessionalReconciliationRequest[REDACTED]"; }
    }
    private final ProfessionalReconciliationService service;
    public ProfessionalReconciliationController(ProfessionalReconciliationService service) { this.service=service; }
    @PostMapping("/professional-reconciliations/{organization}")
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public ResponseEntity<ProfessionalReconciliationService.Result> reconcile(@AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID organization,@Valid @RequestBody Request request) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(service.reconcile(jwt,
                new DeveloperCatalogService.Proof(request.accountId(),request.password(),request.secondFactor(),request.reason()),organization,
                new ProfessionalReconciliationService.Command(request.sourceAccountId(),request.targetAccountId(),request.newAccountPassword(),request.displayName(),request.expectedVersion())));
    }
}
