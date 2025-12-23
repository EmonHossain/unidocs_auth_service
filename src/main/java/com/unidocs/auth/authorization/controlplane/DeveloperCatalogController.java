package com.unidocs.auth.authorization.controlplane;

import java.util.List;
import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@io.swagger.v3.oas.annotations.Hidden
@RequestMapping("${api.version.base-path}/developer")
public class DeveloperCatalogController {
    public record CatalogRequest(UUID accountId,@NotBlank @Size(max=128) String password,@NotBlank @Size(max=64) String secondFactor,
            @NotBlank String kind,UUID after,@Min(1) @Max(100) int limit){
        @Override public String toString(){return "CatalogRequest[REDACTED]";}
    }
    public record RoleRequest(UUID accountId,@NotBlank @Size(max=128) String password,@NotBlank @Size(max=64) String secondFactor,
            @NotBlank @Size(max=128) String roleKey,@NotBlank String status,@NotNull @Size(max=64) List<@NotNull UUID> authorities,
            @Size(max=512) String reason){
        @Override public String toString(){return "RoleRequest[REDACTED]";}
    }
    public record CategoryRequest(UUID accountId,@NotBlank @Size(max=128) String password,@NotBlank @Size(max=64) String secondFactor,
            @NotNull UUID roleId,@NotBlank String status,@Size(max=512) String reason){
        @Override public String toString(){return "CategoryRequest[REDACTED]";}
    }
    public record PolicyRequest(UUID accountId,@NotBlank @Size(max=128) String password,@NotBlank @Size(max=64) String secondFactor,
            @NotBlank String matchMode,boolean requiresScopedAuthorities,@NotBlank String status,@NotNull @Size(min=1,max=64) List<@NotNull UUID> authorities,
            @Size(max=512) String reason){
        @Override public String toString(){return "PolicyRequest[REDACTED]";}
    }
    private final DeveloperCatalogService service;
    public DeveloperCatalogController(DeveloperCatalogService service){this.service=service;}
    @PostMapping("/catalog") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<DeveloperCatalogService.Page> catalog(@AuthenticationPrincipal Jwt jwt,@Valid @RequestBody CatalogRequest request){
        return ResponseEntity.ok().header("Cache-Control","no-store").body(service.catalog(jwt,proof(request.accountId(),request.password(),request.secondFactor()),request.kind(),request.after(),request.limit()));
    }
    @PostMapping("/roles") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<DeveloperCatalogService.Result> createRole(@AuthenticationPrincipal Jwt jwt,@Valid @RequestBody RoleRequest request,
            @RequestHeader(value="If-Match",required=false) String match,@RequestHeader(value="Idempotency-Key",required=false) String key){
        return result(service.role(jwt,proof(request.accountId(),request.password(),request.secondFactor(),request.reason()),null,request.roleKey(),request.status(),request.authorities(),match,key));
    }
    @PutMapping("/roles/{id}") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<DeveloperCatalogService.Result> role(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id,@Valid @RequestBody RoleRequest request,
            @RequestHeader(value="If-Match",required=false) String match,@RequestHeader(value="Idempotency-Key",required=false) String key){
        return result(service.role(jwt,proof(request.accountId(),request.password(),request.secondFactor(),request.reason()),id,request.roleKey(),request.status(),request.authorities(),match,key));
    }
    @PutMapping("/categories/{category}") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<DeveloperCatalogService.Result> category(@AuthenticationPrincipal Jwt jwt,@PathVariable String category,@Valid @RequestBody CategoryRequest request,
            @RequestHeader(value="If-Match",required=false) String match,@RequestHeader(value="Idempotency-Key",required=false) String key){
        return result(service.category(jwt,proof(request.accountId(),request.password(),request.secondFactor(),request.reason()),category,request.roleId(),request.status(),match,key));
    }
    @PutMapping("/operations/{id}/policy") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<DeveloperCatalogService.Result> policy(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id,@Valid @RequestBody PolicyRequest request,
            @RequestHeader(value="If-Match",required=false) String match,@RequestHeader(value="Idempotency-Key",required=false) String key){
        return result(service.policy(jwt,proof(request.accountId(),request.password(),request.secondFactor(),request.reason()),id,request.matchMode(),request.requiresScopedAuthorities(),request.status(),request.authorities(),match,key));
    }
    @PutMapping("/baselines/{category}") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<DeveloperCatalogService.Result> baseline(@AuthenticationPrincipal Jwt jwt,@PathVariable String category,@Valid @RequestBody CategoryRequest request,
            @RequestHeader(value="If-Match",required=false) String match,@RequestHeader(value="Idempotency-Key",required=false) String key){
        return result(service.binding(jwt,proof(request.accountId(),request.password(),request.secondFactor(),request.reason()),"baselines",category,request.roleId(),request.status(),match,key));
    }
    @PutMapping("/relationships/{relationship}") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<DeveloperCatalogService.Result> relationship(@AuthenticationPrincipal Jwt jwt,@PathVariable String relationship,@Valid @RequestBody CategoryRequest request,
            @RequestHeader(value="If-Match",required=false) String match,@RequestHeader(value="Idempotency-Key",required=false) String key){
        return result(service.binding(jwt,proof(request.accountId(),request.password(),request.secondFactor(),request.reason()),"relationships",relationship,request.roleId(),request.status(),match,key));
    }
    @PutMapping("/student-responsibilities/{responsibility}") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public ResponseEntity<DeveloperCatalogService.Result> studentResponsibility(@AuthenticationPrincipal Jwt jwt,@PathVariable String responsibility,@Valid @RequestBody CategoryRequest request,
            @RequestHeader(value="If-Match",required=false) String match,@RequestHeader(value="Idempotency-Key",required=false) String key) {
        return result(service.binding(jwt,proof(request.accountId(),request.password(),request.secondFactor(),request.reason()),"student-responsibilities",responsibility,request.roleId(),request.status(),match,key));
    }
    private static DeveloperCatalogService.Proof proof(UUID account,String password,String factor){return new DeveloperCatalogService.Proof(account,password,factor);}
    private static DeveloperCatalogService.Proof proof(UUID account,String password,String factor,String reason){return new DeveloperCatalogService.Proof(account,password,factor,reason);}
    private static ResponseEntity<DeveloperCatalogService.Result> result(DeveloperCatalogService.Result result){return ResponseEntity.ok().eTag("\""+result.version()+"\"").header("Cache-Control","no-store").body(result);}
}
