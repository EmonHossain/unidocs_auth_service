package com.unidocs.auth.group.personal;

import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("${api.version.base-path}/internal/authorization/personal-groups")
public class PersonalGroupInternalController {
    public record ClosureRequest(UUID after,@Min(1) @Max(100) int limit) { }
    public record ConfirmRequest(@Min(1) long groupVersion,@NotNull UUID noticeBatchId) { }
    private final PersonalGroupClosureService service;
    public PersonalGroupInternalController(PersonalGroupClosureService service){this.service=service;}
    @PostMapping("/closures")
    @PreAuthorize("isAuthenticated() and hasAuthority('SCOPE_iam.authorization.read')")
    public ResponseEntity<PersonalGroupClosureService.Page> closures(Authentication authentication,@Valid @RequestBody ClosureRequest request){
        return ResponseEntity.ok().header("Cache-Control","no-store").body(service.closures(authentication,request.after(),request.limit()));
    }
    @PostMapping("/closures/{groupId}/confirm-notices")
    @PreAuthorize("isAuthenticated() and hasAuthority('SCOPE_iam.authorization.read')")
    public ResponseEntity<PersonalGroupClosureService.Closure> confirm(Authentication authentication,@PathVariable UUID groupId,@Valid @RequestBody ConfirmRequest request){
        return ResponseEntity.ok().header("Cache-Control","no-store").body(service.confirmNotices(authentication,groupId,request.groupVersion(),request.noticeBatchId()));
    }
    @PostMapping("/closures/{groupId}/state")
    @PreAuthorize("isAuthenticated() and hasAuthority('SCOPE_iam.authorization.read')")
    public ResponseEntity<PersonalGroupClosureService.Closure> state(Authentication authentication,@PathVariable UUID groupId){
        return ResponseEntity.ok().header("Cache-Control","no-store").body(service.state(authentication,groupId));
    }
}
