package com.unidocs.auth.group.personal;

import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("${api.version.base-path}/personal/groups")
public class PersonalGroupController {
    public record ActorRequest(@NotNull UUID accountId) { }
    public record CreateRequest(@NotNull UUID accountId,@NotBlank @Size(max=100) String name,@NotNull UUID requestId) { }
    public record InviteRequest(@NotNull UUID accountId,@NotNull UUID recipientAccountId,@NotNull UUID requestId) { }
    private final PersonalGroupService service;
    public PersonalGroupController(PersonalGroupService service){this.service=service;}
    @GetMapping @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<PersonalGroupService.GroupPage> list(@AuthenticationPrincipal Jwt jwt,@RequestParam UUID accountId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") @Min(1) @Max(100) int limit){return response(service.list(jwt,accountId,after,limit));}
    @PostMapping @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<PersonalGroupService.GroupView> create(@AuthenticationPrincipal Jwt jwt,@Valid @RequestBody CreateRequest request){return response(service.create(jwt,request.accountId(),request.name(),request.requestId()));}
    @GetMapping("/{id}") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<PersonalGroupService.GroupView> get(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id,@RequestParam UUID accountId){return response(service.get(jwt,accountId,id));}
    @PostMapping("/{id}/invitations") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<PersonalGroupService.Invitation> invite(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id,@Valid @RequestBody InviteRequest request){return response(service.invite(jwt,request.accountId(),id,request.recipientAccountId(),request.requestId()));}
    @GetMapping("/invitations") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<PersonalGroupService.InvitationPage> invitations(@AuthenticationPrincipal Jwt jwt,@RequestParam UUID accountId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") @Min(1) @Max(100) int limit){return response(service.invitations(jwt,accountId,after,limit));}
    @GetMapping("/{groupId}/invitations") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<PersonalGroupService.InvitationPage> outgoing(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID groupId,@RequestParam UUID accountId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") @Min(1) @Max(100) int limit){return response(service.outgoing(jwt,accountId,groupId,after,limit));}
    @GetMapping("/{groupId}/members") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<PersonalGroupService.MemberPage> members(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID groupId,@RequestParam UUID accountId,@RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") @Min(1) @Max(100) int limit){return response(service.members(jwt,accountId,groupId,after,limit));}
    @PostMapping("/invitations/{id}/accept") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<PersonalGroupService.Invitation> accept(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id,@Valid @RequestBody ActorRequest request){return response(service.respond(jwt,request.accountId(),id,true));}
    @PostMapping("/invitations/{id}/decline") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<PersonalGroupService.Invitation> decline(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id,@Valid @RequestBody ActorRequest request){return response(service.respond(jwt,request.accountId(),id,false));}
    @PostMapping("/{groupId}/invitations/{id}/revoke") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<PersonalGroupService.Invitation> revoke(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID groupId,@PathVariable UUID id,@Valid @RequestBody ActorRequest request){return response(service.revoke(jwt,request.accountId(),groupId,id));}
    @DeleteMapping("/{groupId}/members/{recipientAccountId}") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<Void> remove(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID groupId,@PathVariable UUID recipientAccountId,@RequestParam UUID accountId){service.remove(jwt,accountId,groupId,recipientAccountId,false);return ResponseEntity.noContent().header("Cache-Control","no-store").build();}
    @PostMapping("/{groupId}/leave") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<Void> leave(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID groupId,@Valid @RequestBody ActorRequest request){service.remove(jwt,request.accountId(),groupId,request.accountId(),true);return ResponseEntity.noContent().header("Cache-Control","no-store").build();}
    @PostMapping("/{groupId}/deletion") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<PersonalGroupService.GroupView> deletion(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID groupId,@Valid @RequestBody ActorRequest request){return response(service.scheduleDeletion(jwt,request.accountId(),groupId));}
    @PostMapping("/{groupId}/deletion/cancel") @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public ResponseEntity<PersonalGroupService.GroupView> cancelDeletion(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID groupId,@Valid @RequestBody ActorRequest request){return response(service.cancelDeletion(jwt,request.accountId(),groupId));}
    private static <T> ResponseEntity<T> response(T body){return ResponseEntity.ok().header("Cache-Control","no-store").body(body);}
}
