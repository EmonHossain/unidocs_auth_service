package com.unidocs.auth.registration.api;

import java.net.URI;
import com.unidocs.auth.shared.config.ApiVersionProperties;
import java.util.UUID;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.unidocs.auth.registration.api.RegistrationResponse;
import com.unidocs.auth.registration.application.RegistrationProvisioningService;
import com.unidocs.auth.registration.application.RegistrationService;

@io.swagger.v3.oas.annotations.tags.Tag(name = "Registration", description = "Pending registration, verification and retry-safe account provisioning.")
@RestController
@RequestMapping("${api.version.base-path}/registrations")
public class RegistrationController {
    private final ApiVersionProperties apiVersion;
    private final RegistrationService registrations;
    private final RegistrationProvisioningService provisioning;

    public RegistrationController(RegistrationService registrations, RegistrationProvisioningService provisioning, ApiVersionProperties apiVersion) {
        this.registrations = registrations; this.apiVersion = apiVersion;
        this.provisioning = provisioning;
    }

    @io.swagger.v3.oas.annotations.Operation(summary = "Create pending registration", description = "Start email verification. Pending registrations cannot authorize access.")
    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "201", description = "Pending registration created; verification delivery queued.", useReturnTypeSchema = true)
    @PostMapping
    ResponseEntity<RegistrationResponse> register(@Valid @RequestBody RegistrationRequest request) {
        RegistrationResponse response = registrations.register(request);
        return ResponseEntity.created(URI.create(apiVersion.path("/registrations/" + response.id())))
                .header("Cache-Control", "no-store").body(response);
    }

    @io.swagger.v3.oas.annotations.Operation(summary = "Verify registration", description = "Validate the expiring verification token and mark the registration VERIFIED; provisioning remains separate.")
    @PostMapping("/{id}/verify")
    ResponseEntity<RegistrationResponse> verify(@PathVariable UUID id,
            @Valid @RequestBody VerificationRequest request) {
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(registrations.verify(id, request));
    }

    @io.swagger.v3.oas.annotations.Operation(summary = "Complete registration", description = "Provision user, account, login identity and account group transactionally. Repeated valid completion is idempotent.")
    @PostMapping("/{id}/complete")
    ResponseEntity<RegistrationCompletionResponse> complete(@PathVariable UUID id,
            @Valid @RequestBody RegistrationCompletionRequest request) {
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(provisioning.complete(id, request));
    }
}
