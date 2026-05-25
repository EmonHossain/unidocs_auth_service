package com.unidocs.auth.student;

import java.util.List;
import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("${api.version.base-path}/institutes/{organization}/workspace")
@PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
public class StudentWorkspaceController {
    public record Actor(@NotNull UUID accountId) { }
    public record Invite(@NotNull UUID accountId,@NotNull UUID recipientAccountId,@NotNull UUID requestId) { }
    public record Respond(@NotNull UUID accountId,boolean accept) { }
    public record Deletion(@NotNull UUID accountId,@Positive long expectedVersion,boolean cancel) { }
    public record Revoke(@NotNull UUID accountId,@Positive long expectedVersion) { }
    private final StudentWorkspaceService service;
    public StudentWorkspaceController(StudentWorkspaceService service) { this.service=service; }
    @PostMapping("/semesters")
    public StudentWorkspaceService.Semester semester(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@Valid @RequestBody StudentWorkspaceService.SemesterCommand command) { return service.semester(jwt,organization,command); }
    @GetMapping("/semesters")
    public List<StudentWorkspaceService.Semester> semesters(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@RequestParam UUID accountId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") int limit) { return service.semesters(jwt,organization,accountId,after,limit); }
    @PostMapping("/courses")
    public StudentWorkspaceService.Course create(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@Valid @RequestBody StudentWorkspaceService.CatalogCommand command) { return service.catalog(jwt,organization,null,command); }
    @PutMapping("/courses/{course}")
    public StudentWorkspaceService.Course update(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@PathVariable UUID course,@Valid @RequestBody StudentWorkspaceService.CatalogCommand command) { return service.catalog(jwt,organization,course,command); }
    @GetMapping("/courses")
    public List<StudentWorkspaceService.Course> courses(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@RequestParam UUID accountId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") int limit) { return service.courses(jwt,organization,accountId,after,limit); }
    @PostMapping("/courses/{course}/join")
    public StudentWorkspaceService.Course join(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@PathVariable UUID course,@Valid @RequestBody Actor command) { return service.join(jwt,organization,command.accountId(),course); }
    @PostMapping("/study-groups")
    public StudentWorkspaceService.Study createStudy(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@Valid @RequestBody StudentWorkspaceService.StudyCommand command) { return service.createStudy(jwt,organization,command); }
    @GetMapping("/courses/{course}/study-groups")
    public List<StudentWorkspaceService.Study> studies(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@PathVariable UUID course,@RequestParam UUID accountId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") int limit) { return service.studies(jwt,organization,accountId,course,after,limit); }
    @PostMapping("/study-groups/{group}/invitations")
    public StudentWorkspaceService.Invitation invite(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@PathVariable UUID group,@Valid @RequestBody Invite command) { return service.invite(jwt,organization,command.accountId(),group,command.recipientAccountId(),command.requestId()); }
    @PostMapping("/study-invitations/{id}/respond")
    public StudentWorkspaceService.Invitation respond(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@PathVariable UUID id,@Valid @RequestBody Respond command) { return service.respond(jwt,organization,command.accountId(),id,command.accept()); }
    @GetMapping("/study-invitations")
    public List<StudentWorkspaceService.Invitation> invitations(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@RequestParam UUID accountId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") int limit) { return service.invitations(jwt,organization,accountId,after,limit); }
    @GetMapping("/study-groups/{group}/members")
    public List<StudentWorkspaceService.Member> members(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@PathVariable UUID group,@RequestParam UUID accountId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") int limit) { return service.members(jwt,organization,accountId,group,after,limit); }
    @PostMapping("/study-groups/{group}/invitations/{id}/revoke")
    public StudentWorkspaceService.Invitation revoke(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@PathVariable UUID group,@PathVariable UUID id,@Valid @RequestBody Revoke command) { return service.revokeInvitation(jwt,organization,command.accountId(),group,id,command.expectedVersion()); }
    @PostMapping("/study-groups/{group}/deletion")
    public StudentWorkspaceService.Study deletion(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@PathVariable UUID group,@Valid @RequestBody Deletion command) { return service.deletion(jwt,organization,command.accountId(),group,command.expectedVersion(),command.cancel()); }
    @PostMapping("/study-groups/{group}/leave")
    public void leave(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@PathVariable UUID group,@Valid @RequestBody Actor command) { service.leave(jwt,organization,command.accountId(),group); }
    @PostMapping("/reports")
    public StudentWorkspaceService.Report report(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@Valid @RequestBody StudentWorkspaceService.ReportCommand command) { return service.report(jwt,organization,command); }
    @GetMapping("/reports")
    public List<StudentWorkspaceService.Report> reports(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@RequestParam UUID accountId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") int limit) { return service.reports(jwt,organization,accountId,after,limit); }
    @GetMapping("/reports/{id}")
    public StudentWorkspaceService.ReportDetail reportDetail(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@PathVariable UUID id,@RequestParam UUID accountId) { return service.reportDetail(jwt,organization,accountId,id); }
    @PutMapping("/reports/{id}/review")
    public StudentWorkspaceService.Report review(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@PathVariable UUID id,@Valid @RequestBody StudentWorkspaceService.ReviewCommand command) { return service.review(jwt,organization,id,command); }
    @GetMapping("/notices")
    public List<StudentWorkspaceService.Notice> notices(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organization,@RequestParam UUID accountId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") int limit) { return service.notices(jwt,organization,accountId,after,limit); }
}
