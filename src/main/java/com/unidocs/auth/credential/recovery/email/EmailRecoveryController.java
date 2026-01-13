package com.unidocs.auth.credential.recovery.email;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
@Tag(name = "Password recovery", description = "Verified-email password recovery.")
@RestController
@RequestMapping("${api.version.base-path}/auth")
public class EmailRecoveryController {
    private final EmailPasswordRecoveryService service;
    public EmailRecoveryController(EmailPasswordRecoveryService service) { this.service=service; }
    @Operation(summary = "Request password recovery", description = "Requests an email recovery code. The accepted response does not disclose whether the account exists.")
    @ApiResponse(responseCode = "202", description = "Recovery request accepted without disclosing account existence.")
    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgot(@Valid @RequestBody EmailRecoveryRequests.Forgot request) {
        service.forgot(request);
        return ResponseEntity.accepted().header("Cache-Control","no-store").build();
    }
    @Operation(summary = "Reset a password", description = "Verifies the recovery code and sets a new password subject to expiry and attempt limits.")
    @ApiResponse(responseCode = "204", description = "Password reset completed.")
    @PostMapping("/reset-password")
    public ResponseEntity<Void> reset(@Valid @RequestBody EmailRecoveryRequests.Reset request) {
        service.reset(request);
        return ResponseEntity.noContent().header("Cache-Control","no-store").build();
    }
}
