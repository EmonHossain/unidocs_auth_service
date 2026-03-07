package com.unidocs.auth.organization.professional;

import java.util.List;
import java.util.UUID;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("${api.version.base-path}")
@PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
public class ProfessionalPolicyController {
    private final ProfessionalPolicyService service;
    public ProfessionalPolicyController(ProfessionalPolicyService service) { this.service=service; }
    @PutMapping("/organizations/{organization}/professional/responsibilities")
    public ResponseEntity<Long> responsibility(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@Valid @RequestBody ProfessionalPolicyService.Responsibility request) {
        return noStore(service.responsibility(sid(jwt),UUID.fromString(jwt.getSubject()),organization,request));
    }
    @PutMapping("/organizations/{organization}/professional/restrictions")
    public ResponseEntity<Long> restriction(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@Valid @RequestBody ProfessionalPolicyService.Restriction request) {
        return noStore(service.restriction(sid(jwt),UUID.fromString(jwt.getSubject()),organization,request));
    }
    @GetMapping("/me/professional-notices")
    public ResponseEntity<List<ProfessionalPolicyService.Notice>> notices(@AuthenticationPrincipal Jwt jwt,@RequestParam UUID accountId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") int limit) {
        return noStore(service.notices(sid(jwt),UUID.fromString(jwt.getSubject()),accountId,after,limit));
    }
    @GetMapping("/organizations/{organization}/professional/members")
    public ResponseEntity<List<ProfessionalPolicyService.Member>> members(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,
            @RequestParam UUID accountId,@RequestParam(required=false) UUID groupId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") int limit) {
        return noStore(service.members(sid(jwt),UUID.fromString(jwt.getSubject()),organization,accountId,groupId,after,limit));
    }
    @GetMapping("/organizations/{organization}/professional/responsibilities")
    public ResponseEntity<List<ProfessionalPolicyService.ResponsibilityView>> responsibilities(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,
            @RequestParam UUID accountId,@RequestParam(required=false) UUID groupId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") int limit) {
        return noStore(service.responsibilities(sid(jwt),UUID.fromString(jwt.getSubject()),organization,accountId,groupId,after,limit));
    }
    @GetMapping("/organizations/{organization}/professional/restrictions")
    public ResponseEntity<List<ProfessionalPolicyService.RestrictionView>> restrictions(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,
            @RequestParam UUID accountId,@RequestParam(required=false) UUID groupId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") int limit) {
        return noStore(service.restrictions(sid(jwt),UUID.fromString(jwt.getSubject()),organization,accountId,groupId,after,limit));
    }
    /** Returns projection progress after scoped access-management authorization.
     * @param jwt verified product token
     * @param organization selected organization
     * @param accountId selected account grant
     * @return no-store projection status response
     */
    @GetMapping("/organizations/{organization}/professional/projection-status")
    public ResponseEntity<ProfessionalPolicyService.ProjectionStatus> projectionStatus(@AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID organization,@RequestParam UUID accountId) {
        return noStore(service.projectionStatus(sid(jwt),UUID.fromString(jwt.getSubject()),organization,accountId));
    }
    /** Returns the current configured choices available to scoped access managers.
     * @param jwt verified product token
     * @param organization selected organization
     * @param accountId selected account grant
     * @return no-store access catalog response
     */
    @GetMapping("/organizations/{organization}/professional/access-catalog")
    public ResponseEntity<ProfessionalPolicyService.AccessCatalog> accessCatalog(@AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID organization,@RequestParam UUID accountId) {
        return noStore(service.accessCatalog(sid(jwt),UUID.fromString(jwt.getSubject()),organization,accountId));
    }
    /** Returns a redacted effective-access preview for one current member and configured operation.
     * @param jwt verified product token
     * @param organization selected organization
     * @param accountId manager's account grant
     * @param targetAccountId member account to inspect
     * @param operationId configured operation
     * @param groupId optional managed group scope
     * @return no-store allow or deny preview
     */
    @GetMapping("/organizations/{organization}/professional/access-preview")
    public ResponseEntity<ProfessionalPolicyService.AccessPreview> preview(@AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID organization,@RequestParam UUID accountId,@RequestParam UUID targetAccountId,
            @RequestParam UUID operationId,@RequestParam(required=false) UUID groupId) {
        return noStore(service.preview(sid(jwt),UUID.fromString(jwt.getSubject()),organization,accountId,
                targetAccountId,groupId,operationId));
    }
    /** Lists scoped access-management audit metadata for the selected organization.
     * @param jwt verified product token
     * @param organization selected organization
     * @param accountId manager's account grant
     * @param after exclusive audit cursor
     * @param limit bounded page size
     * @return no-store audit page
     */
    @GetMapping("/organizations/{organization}/professional/audit")
    public ResponseEntity<List<ProfessionalPolicyService.AuditEntry>> audit(@AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID organization,@RequestParam UUID accountId,@RequestParam(required=false) UUID after,
            @RequestParam(defaultValue="50") int limit) {
        return noStore(service.audit(sid(jwt),UUID.fromString(jwt.getSubject()),organization,accountId,after,limit));
    }
    private static UUID sid(Jwt jwt) { return UUID.fromString(jwt.getClaimAsString("sid")); }
    private static <T> ResponseEntity<T> noStore(T value) { return ResponseEntity.ok().header("Cache-Control","no-store").body(value); }
}
