package com.unidocs.auth.authorization.api;

import com.unidocs.auth.authorization.application.InternalAuthorizationService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("${api.version.base-path}/internal/authorization")
public class InternalAuthorizationController {
    private final InternalAuthorizationService authorization;
    public InternalAuthorizationController(InternalAuthorizationService authorization) { this.authorization = authorization; }

    @PostMapping("/account")
    ResponseEntity<InternalAccountAuthorizationResponse> account(
            @RequestHeader(name = "X-Delegated-Authorization", required = false) String delegated,
            @Valid @RequestBody InternalAccountAuthorizationRequest request) {
        return ResponseEntity.ok().header("Cache-Control", "no-store")
                .body(authorization.authorizeAccount(delegated, request));
    }

    @PostMapping("/group")
    ResponseEntity<InternalGroupAuthorizationResponse> group(
            @RequestHeader(name = "X-Delegated-Authorization", required = false) String delegated,
            @Valid @RequestBody InternalGroupAuthorizationRequest request) {
        return ResponseEntity.ok().header("Cache-Control", "no-store")
                .body(authorization.authorizeGroup(delegated, request));
    }

    @PostMapping("/organization")
    ResponseEntity<InternalAuthorizationResponse> organization(
            @RequestHeader(name = "X-Delegated-Authorization", required = false) String delegated,
            @Valid @RequestBody InternalAuthorizationRequest request) {
        return ResponseEntity.ok().header("Cache-Control", "no-store")
                .body(authorization.authorize(delegated, request));
    }
}
