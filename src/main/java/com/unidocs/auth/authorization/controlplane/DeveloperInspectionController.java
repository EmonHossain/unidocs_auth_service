package com.unidocs.auth.authorization.controlplane;

import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Operator-only redacted inspection; never exposes SpiceDB admin credentials or raw tuple writes. */
@io.swagger.v3.oas.annotations.Hidden
@RestController
@ConditionalOnProperty(name="auth.developer.operator.enabled",havingValue="true")
@RequestMapping("${api.version.base-path}/developer")
public class DeveloperInspectionController {
    public record Request(@NotBlank String password,@NotBlank String secondFactor,@NotBlank String kind,
            UUID organizationId,UUID targetAccountId,UUID operationId,UUID after,@Min(1) @Max(100) int limit) {
        @Override public String toString() { return "Request[REDACTED]"; }
    }
    private final DeveloperInspectionService service;
    /** Wires the operator-only inspection use case.
     * @param service bounded inspection service
     */
    public DeveloperInspectionController(DeveloperInspectionService service) { this.service=service; }
    /** Consumes a fresh operator factor for each inspection request.
     * @param jwt verified operator token
     * @param request view selector and current proof
     * @return redacted, no-store inspection data
     */
    @PostMapping("/inspection")
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public ResponseEntity<DeveloperInspectionService.Inspection> inspect(@AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody Request request) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(service.inspect(jwt,
                new DeveloperInspectionService.Request(request.password(),request.secondFactor(),request.kind(),
                        request.organizationId(),request.targetAccountId(),request.operationId(),request.after(),request.limit())));
    }
}
