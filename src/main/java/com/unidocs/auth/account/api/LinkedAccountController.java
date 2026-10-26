package com.unidocs.auth.account.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import com.unidocs.auth.account.application.LinkedAccountService;

@Tag(name = "Linked accounts", description = "Account challenges and navigation preferences.")
@RestController
@RequestMapping("${api.version.base-path}")
public class LinkedAccountController {
    private final LinkedAccountService accounts;
    public LinkedAccountController(LinkedAccountService accounts) { this.accounts = accounts; }
    @Operation(summary = "Create an account challenge", description = "Starts a challenge for the selected linked account and purpose. Linking alone grants no access.")
    @PostMapping("/accounts/{accountId}/challenges")
    ResponseEntity<LinkedAccountService.ChallengeResponse> challenge(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID accountId,
            @Valid @RequestBody ChallengeRequest request) {
        return noStore(accounts.challenge(session(jwt), subject(jwt), accountId, request));
    }
    @Operation(summary = "Complete an account challenge", description = "Verifies the challenge proof and performs its requested action. Organization authorization remains independently required.")
    @PostMapping("/accounts/{accountId}/challenges/{id}/complete")
    ResponseEntity<LinkedAccountService.ActionResponse> complete(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID accountId,
            @PathVariable UUID id, @Valid @RequestBody AccountProofRequest request) {
        return noStore(accounts.complete(session(jwt), subject(jwt), accountId, id, request));
    }
    public record PreferredAccountRequest(@NotNull UUID accountId) { }
    public record PreferredAccountResponse(UUID preferredAccountId) { }
    @Operation(summary = "Set the preferred account", description = "Updates the navigation preference without granting authorization or switching server-side session state.")
    @PutMapping("/me/preferred-account")
    ResponseEntity<PreferredAccountResponse> preferred(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody PreferredAccountRequest request) {
        return noStore(new PreferredAccountResponse(accounts.preferred(session(jwt), subject(jwt), request.accountId())));
    }
    private static UUID session(Jwt jwt) { return UUID.fromString(jwt.getClaimAsString("sid")); }
    private static UUID subject(Jwt jwt) { return UUID.fromString(jwt.getSubject()); }
    private static <T> ResponseEntity<T> noStore(T body) { return ResponseEntity.ok().header("Cache-Control", "no-store").body(body); }
}
