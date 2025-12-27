package com.unidocs.auth.authorization.controlplane;

import java.util.UUID;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Dedicated operator authentication routes, hidden from product API discovery. */
@io.swagger.v3.oas.annotations.Hidden
@RestController
@org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(name="auth.developer.operator.enabled",havingValue="true")
@RequestMapping("${api.version.base-path}/developer/auth")
public class DeveloperOperatorAuthController {
    public record Start(@NotBlank String activation,@NotBlank String bootstrapPassword,@NotBlank String username,
            @NotBlank @Size(min=15,max=128) String newPassword,@NotBlank String email) {
        @Override public String toString() { return "Start[REDACTED]"; }
    }
    public record Complete(@NotBlank String activation,@NotBlank String emailCode) {
        @Override public String toString() { return "Complete[REDACTED]"; }
    }
    public record Login(@NotBlank String username,@NotBlank String password) {
        @Override public String toString() { return "Login[REDACTED]"; }
    }
    public record Refresh(@NotNull UUID sessionId,@NotBlank String refreshSecret) {
        @Override public String toString() { return "Refresh[REDACTED]"; }
    }
    public record Change(@NotBlank String currentPassword,@NotBlank String factor,
            @NotBlank @Size(min=15,max=128) String newPassword,@NotBlank String confirmation) {
        @Override public String toString() { return "Change[REDACTED]"; }
    }
    public record Forgot(@NotBlank String username,@NotBlank String email) { }
    public record Reset(@NotBlank String username,@NotBlank String email,@NotBlank String token,
            @NotBlank String recoveryCode,@NotBlank @Size(min=15,max=128) String newPassword,@NotBlank String confirmation) {
        @Override public String toString() { return "Reset[REDACTED]"; }
    }
    public record RotateCodes(@NotBlank String password,@NotBlank String factor) {
        @Override public String toString() { return "RotateCodes[REDACTED]"; }
    }
    private final DeveloperOperatorAuthService service;
    private final DeveloperOperatorRecoveryService recovery;
    /** Delegates operator authentication to its separate credential realm.
     * @param service operator authentication use cases
     * @param recovery separate operator credential recovery
     */
    public DeveloperOperatorAuthController(DeveloperOperatorAuthService service,DeveloperOperatorRecoveryService recovery) {
        this.service=service;this.recovery=recovery;
    }

    /** Starts email verification with the installation-owned activation secret.
     * @param request first-use setup inputs
     * @param servlet current HTTP request
     * @return accepted response without secrets
     */
    @PostMapping("/setup/start")
    public ResponseEntity<Void> start(@Valid @RequestBody Start request,HttpServletRequest servlet) {
        service.startSetup(new DeveloperOperatorAuthService.SetupStart(request.activation(),request.bootstrapPassword(),
                request.username(),request.newPassword(),request.email()),servlet.getRemoteAddr());
        return ResponseEntity.accepted().header("Cache-Control","no-store").build();
    }
    /** Completes first-use enrollment and returns the one-time factor set once.
     * @param request installation and email proofs
     * @return no-store enrollment response
     */
    @PostMapping("/setup/complete")
    public ResponseEntity<DeveloperOperatorAuthService.Enrollment> complete(@Valid @RequestBody Complete request) {
        return ResponseEntity.ok().header("Cache-Control","no-store")
                .body(service.completeSetup(new DeveloperOperatorAuthService.SetupComplete(request.activation(),request.emailCode())));
    }
    /** Opens a session for the operator principal only.
     * @param request operator credentials
     * @param servlet current HTTP request
     * @return no-store operator session response
     */
    @PostMapping("/login")
    public ResponseEntity<DeveloperOperatorAuthService.Session> login(@Valid @RequestBody Login request,HttpServletRequest servlet) {
        return ResponseEntity.ok().header("Cache-Control","no-store")
                .body(service.login(new DeveloperOperatorAuthService.Login(request.username(),request.password()),servlet.getRemoteAddr()));
    }
    /** Rotates the separate operator refresh secret.
     * @param request current session and refresh proof
     * @return no-store rotated session response
     */
    @PostMapping("/refresh")
    public ResponseEntity<DeveloperOperatorAuthService.Session> refresh(@Valid @RequestBody Refresh request) {
        return ResponseEntity.ok().header("Cache-Control","no-store")
                .body(service.refresh(new DeveloperOperatorAuthService.Refresh(request.sessionId(),request.refreshSecret())));
    }
    /** Sends recovery instructions without revealing whether the operator exists.
     * @param request established operator username and email
     * @param servlet current HTTP request
     * @return identical accepted response for eligible and ineligible selectors
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgot(@Valid @RequestBody Forgot request,HttpServletRequest servlet) {
        recovery.request(new DeveloperOperatorRecoveryService.RecoveryRequest(request.username(),request.email()),servlet.getRemoteAddr());
        return ResponseEntity.accepted().header("Cache-Control","no-store").build();
    }
    /** Resets a forgotten password only with email and independent offline proofs.
     * @param request recovery proof, offline code, and replacement password
     * @return one-time replacement proofs without a login session
     */
    @PostMapping("/reset-password")
    public ResponseEntity<DeveloperOperatorRecoveryService.NewProofs> reset(@Valid @RequestBody Reset request) {
        return ResponseEntity.ok().header("Cache-Control","no-store")
                .body(recovery.complete(new DeveloperOperatorRecoveryService.RecoveryCompletion(request.username(),request.email(),
                        request.token(),request.recoveryCode(),request.newPassword(),request.confirmation())));
    }
    /** Changes the operator password with a fresh current-session factor.
     * @param jwt verified operator identity
     * @param request current and replacement credentials
     * @return one-time replacement proofs
     */
    @PostMapping("/change-password")
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public ResponseEntity<DeveloperOperatorRecoveryService.NewProofs> change(@AuthenticationPrincipal Jwt jwt,@Valid @RequestBody Change request) {
        return ResponseEntity.ok().header("Cache-Control","no-store")
                .body(recovery.change(jwt,new DeveloperOperatorRecoveryService.CredentialChange(request.currentPassword(),
                        request.factor(),request.newPassword(),request.confirmation())));
    }
    /** Replaces all independent recovery codes after current proof.
     * @param jwt verified operator identity
     * @param request current password and one-use factor
     * @return replacement recovery codes shown once
     */
    @PostMapping("/recovery-codes/rotate")
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public ResponseEntity<java.util.List<String>> rotateCodes(@AuthenticationPrincipal Jwt jwt,@Valid @RequestBody RotateCodes request) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(recovery.rotateRecoveryCodes(jwt,request.password(),request.factor()));
    }
    /** Replaces one-use catalog factors after current independent proof.
     * @param jwt verified operator identity
     * @param request current password and factor
     * @return replacement catalog factors shown once
     */
    @PostMapping("/factors/rotate")
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public ResponseEntity<java.util.List<String>> rotateFactors(@AuthenticationPrincipal Jwt jwt,@Valid @RequestBody RotateCodes request) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(recovery.rotateFactors(jwt,request.password(),request.factor()));
    }
    /** Closes the current operator session.
     * @param jwt verified current operator token
     * @return no-content response
     */
    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal Jwt jwt) {
        service.logout(UUID.fromString(jwt.getSubject()),UUID.fromString(jwt.getClaimAsString("sid")));
        return ResponseEntity.noContent().header("Cache-Control","no-store").build();
    }
}
