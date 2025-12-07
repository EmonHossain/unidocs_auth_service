package com.unidocs.auth.authorization.api;

import com.unidocs.auth.authorization.application.OperationAuthorizationService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("${api.version.base-path}/internal/authorization")
public class OperationAuthorizationController {
    private final OperationAuthorizationService authorization;
    public OperationAuthorizationController(OperationAuthorizationService authorization) { this.authorization = authorization; }

    @PostMapping({"/operations/evaluate", "/operations/validate"})
    public ResponseEntity<OperationAuthorizationResponse> evaluate(Authentication service,
            @RequestHeader(name = "X-Delegated-Authorization", required = false) String delegated,
            @Valid @RequestBody OperationAuthorizationRequest request) {
        return noStore(authorization.evaluate(service, delegated, request));
    }

    @PostMapping("/individual-recipient")
    public ResponseEntity<IndividualRecipientResponse> recipient(Authentication service,
            @RequestHeader(name = "X-Delegated-Authorization", required = false) String delegated,
            @Valid @RequestBody IndividualRecipientRequest request) {
        return noStore(authorization.recipient(service, delegated, request));
    }

    @PostMapping("/professional-recipient")
    public ResponseEntity<ProfessionalRecipientResponse> professionalRecipient(Authentication service,
            @RequestHeader(name="X-Delegated-Authorization",required=false) String delegated,
            @Valid @RequestBody ProfessionalRecipientRequest request) {
        return noStore(authorization.professionalRecipient(service,delegated,request));
    }

    @PostMapping("/personal-group")
    public ResponseEntity<PersonalGroupAuthorizationResponse> group(Authentication service,
            @RequestHeader(name = "X-Delegated-Authorization", required = false) String delegated,
            @Valid @RequestBody PersonalGroupAuthorizationRequest request) {
        return noStore(authorization.personalGroup(service, delegated, request));
    }

    private static <T> ResponseEntity<T> noStore(T value) {
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(value);
    }
}
