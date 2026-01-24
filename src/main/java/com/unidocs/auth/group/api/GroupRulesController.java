package com.unidocs.auth.group.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import com.unidocs.auth.group.application.*;
import com.unidocs.auth.group.domain.GroupRule;
import com.unidocs.auth.group.persistence.AcademicRepository;

@Tag(name = "Group rules and enrollment", description = "Discovery rules, joining, invitations and trusted academic enrollment.")
@RestController
@RequestMapping("${api.version.base-path}/organizations/{organizationId}")
@org.springframework.security.access.prepost.PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
public class GroupRulesController {
    private final GroupRuleService rules;
    private final AcademicEnrollmentService academics;
    private final GroupInvitationService invitations;
    public GroupRulesController(GroupRuleService rules,AcademicEnrollmentService academics,GroupInvitationService invitations) {
        this.rules=rules;this.academics=academics;this.invitations=invitations;
    }
    @Operation(summary = "Configure group rules", description = "An authorized administrator configures discovery and joining rules for this group.")
    @PutMapping("/groups/{groupId}/rules")
    ResponseEntity<GroupRule> configure(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@PathVariable UUID groupId,
            @Valid @RequestBody GroupRuleRequests.Configure command) {
        return response(rules.configure(sid(jwt),subject(jwt),organizationId,groupId,command));
    }
    @Operation(summary = "Get group rules", description = "Returns the group's rules to an authorized managing account.")
    @GetMapping("/groups/{groupId}/rules")
    ResponseEntity<GroupRule> rule(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@PathVariable UUID groupId,@RequestParam UUID accountId) {
        return response(rules.managedRule(sid(jwt),subject(jwt),organizationId,accountId,groupId));
    }
    @Operation(summary = "Discover groups", description = "Returns currently discoverable groups after applying organization, account and enrollment visibility rules.")
    @GetMapping("/discoverable-groups")
    ResponseEntity<GroupRuleService.Page> discover(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@RequestParam UUID accountId,
            @RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") @Min(1) @Max(100) int limit) {
        return response(rules.discover(sid(jwt),subject(jwt),organizationId,accountId,after,limit));
    }
    @Operation(summary = "Get a discoverable group", description = "Returns group details only when current discovery rules allow visibility.")
    @GetMapping("/discoverable-groups/{groupId}")
    ResponseEntity<GroupRuleService.Discovered> detail(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@PathVariable UUID groupId,@RequestParam UUID accountId) {
        return response(rules.detail(sid(jwt),subject(jwt),organizationId,accountId,groupId));
    }
    @Operation(summary = "Join an open group", description = "Creates membership when current group joining rules permit immediate joining.")
    @PostMapping("/groups/{groupId}/join")
    ResponseEntity<GroupMembershipResponse> join(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@PathVariable UUID groupId,
            @Valid @RequestBody GroupRuleRequests.Join command) {
        return response(rules.join(sid(jwt),subject(jwt),organizationId,groupId,command));
    }
    @Operation(summary = "Create an academic semester", description = "An organization owner or administrator creates an immutable semester interval.")
    @PostMapping("/academic-semesters")
    ResponseEntity<AcademicRepository.Semester> semester(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@Valid @RequestBody GroupRuleRequests.Semester command) {
        return response(academics.createSemester(sid(jwt),subject(jwt),organizationId,command));
    }
    @Operation(summary = "List academic semesters", description = "Returns organization semester definitions using cursor pagination.")
    @GetMapping("/academic-semesters")
    ResponseEntity<AcademicEnrollmentService.Semesters> semesters(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@RequestParam UUID accountId,
            @RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") @Min(1) @Max(100) int limit) {
        return response(academics.semesters(sid(jwt),subject(jwt),organizationId,accountId,after,limit));
    }
    @Operation(summary = "Replace trusted course enrollment", description = "An organization owner or administrator replaces a student's course list using a request ID and expected version.")
    @PutMapping("/course-enrollment")
    ResponseEntity<AcademicEnrollmentService.EnrollmentView> enrollment(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@Valid @RequestBody GroupRuleRequests.Enrollment command) {
        return response(academics.replace(sid(jwt),subject(jwt),organizationId,command));
    }
    @Operation(summary = "Get my course enrollment", description = "Returns the selected account's current trusted course enrollment.")
    @GetMapping("/me/course-enrollment")
    ResponseEntity<AcademicEnrollmentService.EnrollmentView> enrollment(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@RequestParam UUID accountId) {
        return response(academics.mine(sid(jwt),subject(jwt),organizationId,accountId));
    }
    @Operation(summary = "Invite an account to a group", description = "An authorized group administrator issues an account-scoped group invitation.")
    @PostMapping("/groups/{groupId}/invitations")
    ResponseEntity<GroupInvitationService.View> invite(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@PathVariable UUID groupId,
            @Valid @RequestBody GroupInvitationRequests.Issue command) {
        return response(invitations.issue(sid(jwt),subject(jwt),organizationId,groupId,command));
    }
    @Operation(summary = "Accept a group invitation", description = "Accepts an invitation subject to current account, organization and group eligibility.")
    @PostMapping("/groups/{groupId}/invitations/{invitationId}/accept")
    ResponseEntity<GroupInvitationService.View> accept(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@PathVariable UUID groupId,
            @PathVariable UUID invitationId,@Valid @RequestBody GroupInvitationRequests.Action command) {
        return response(invitations.act(sid(jwt),subject(jwt),organizationId,groupId,invitationId,command,true));
    }
    @Operation(summary = "Revoke a group invitation", description = "An authorized group administrator revokes an outstanding invitation.")
    @PostMapping("/groups/{groupId}/invitations/{invitationId}/revoke")
    ResponseEntity<GroupInvitationService.View> revoke(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@PathVariable UUID groupId,
            @PathVariable UUID invitationId,@Valid @RequestBody GroupInvitationRequests.Action command) {
        return response(invitations.act(sid(jwt),subject(jwt),organizationId,groupId,invitationId,command,false));
    }
    @Operation(summary = "List my group invitations", description = "Returns the selected account's group invitations using cursor pagination.")
    @GetMapping("/me/group-invitations")
    ResponseEntity<GroupInvitationService.Page> invitations(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@RequestParam UUID accountId,
            @RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") @Min(1) @Max(100) int limit) {
        return response(invitations.mine(sid(jwt),subject(jwt),organizationId,accountId,after,limit));
    }
    private static <T> ResponseEntity<T> response(T body) { return ResponseEntity.ok().header("Cache-Control","no-store").body(body); }
    private static UUID sid(Jwt jwt) { return UUID.fromString(jwt.getClaimAsString("sid")); }
    private static UUID subject(Jwt jwt) { return UUID.fromString(jwt.getSubject()); }
}
