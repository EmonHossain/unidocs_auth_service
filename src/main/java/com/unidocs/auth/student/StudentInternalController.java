package com.unidocs.auth.student;

import java.util.List;
import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("${api.version.base-path}/internal/authorization/student-workspaces")
public class StudentInternalController {
    public record Page(UUID after,@Min(1) @Max(100) int limit) { }
    public record Ready(@NotNull String kind,@NotNull UUID id,@NotNull UUID workspaceId,@Positive long expectedVersion) { }
    public record Contributors(@NotNull UUID organizationId,UUID after,@Min(1) @Max(100) int limit) { }
    private final StudentProvisioningService service;
    public StudentInternalController(StudentProvisioningService service) { this.service=service; }
    @PostMapping("/contributors")
    public StudentProvisioningService.Contributors contributors(Authentication authentication,@Valid @RequestBody Contributors request) { return service.contributors(authentication,request.organizationId(),request.after(),request.limit()); }
    @PostMapping("/pending")
    public List<StudentProvisioningService.Intent> pending(Authentication authentication,@Valid @RequestBody Page page) { return service.pending(authentication,page.after(),page.limit()); }
    @PostMapping("/ready")
    public java.util.Map<String,String> ready(Authentication authentication,@Valid @RequestBody Ready request) {
        service.ready(authentication,request.kind(),request.id(),request.workspaceId(),request.expectedVersion());return java.util.Map.of("status","READY");
    }
}
