package com.unidocs.auth.security.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import com.unidocs.auth.authentication.browser.BrowserRefreshConfiguration;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(properties={"api.version.base-path=/api/v7",
        "auth.browser-refresh.allowed-origins=https://app.example.com"})
@Import(BrowserRefreshConfiguration.class)
class ApiVersionMappingTests extends SecurityConfigurationTests {
    @Test
    void creationLocationsUseConfiguredPrefix() throws Exception {
        java.util.UUID id = java.util.UUID.fromString("00000000-0000-0000-0000-000000000001");
        String base = apiVersion.basePath();
        org.mockito.Mockito.when(registrations.register(org.mockito.ArgumentMatchers.any()))
                .thenReturn(new com.unidocs.auth.registration.api.RegistrationResponse(id,
                        com.unidocs.auth.registration.domain.RegistrationStatus.PENDING_VERIFICATION, java.time.Instant.now()));
        mvc.perform(post(base + "/registrations").contentType("application/json")
                .content("{\"displayName\":\"Tester\",\"email\":\"tester@example.com\",\"password\":\"long-test-password\"}"))
                .andExpect(status().isCreated()).andExpect(header().string("Location", base + "/registrations/" + id));

        org.mockito.Mockito.when(invitations.issue(org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any()))
                .thenReturn(new com.unidocs.auth.organization.api.InvitationResponse(id,id,null,java.time.Instant.now()));
        mvc.perform(post(base + "/organizations/" + id + "/invitations").with(principal(id)).contentType("application/json")
                .content("{\"accountId\":\"" + id + "\",\"email\":\"invitee@example.com\"}"))
                .andExpect(status().isCreated()).andExpect(header().string("Location", base + "/organizations/" + id + "/invitations/" + id));

        org.mockito.Mockito.when(groups.create(org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any()))
                .thenReturn(new com.unidocs.auth.group.api.GroupResponse(id,id,null,"Test",null,null,1,null,null));
        mvc.perform(post(base + "/organizations/" + id + "/groups").with(principal(id)).contentType("application/json")
                .content("{\"accountId\":\"" + id + "\",\"requestId\":\"" + id + "\",\"name\":\"Test\",\"type\":\"DEPARTMENT\"}"))
                .andExpect(status().isCreated()).andExpect(header().string("Location", base + "/organizations/" + id + "/groups/" + id + "?accountId=" + id));

        org.mockito.Mockito.when(groupJoins.submit(org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any()))
                .thenReturn(new com.unidocs.auth.group.api.GroupJoinResponse(id,id,id,id,id,"MEMBER","Join",null,1,null,null,null,null,null,null));
        mvc.perform(post(base + "/organizations/" + id + "/groups/" + id + "/join-requests").with(principal(id)).contentType("application/json")
                .content("{\"accountId\":\"" + id + "\",\"requestId\":\"" + id + "\",\"requestedRole\":\"MEMBER\",\"reason\":\"Join\"}"))
                .andExpect(status().isCreated()).andExpect(header().string("Location", base + "/organizations/" + id + "/me/group-join-requests?accountId=" + id));

        org.mockito.Mockito.when(groupMemberships.assign(org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any()))
                .thenReturn(new com.unidocs.auth.group.api.GroupMembershipResponse(id,id,id,id,id,"MEMBER",null,null,null,null,null,null,1,null,null,true,false));
        mvc.perform(post(base + "/organizations/" + id + "/groups/" + id + "/memberships").with(principal(id)).contentType("application/json")
                .content("{\"accountId\":\"" + id + "\",\"requestId\":\"" + id + "\",\"memberAccountId\":\"" + id + "\",\"role\":\"MEMBER\",\"validFrom\":\"2026-10-08T00:00:00Z\"}"))
                .andExpect(status().isCreated()).andExpect(header().string("Location", base + "/organizations/" + id + "/groups/" + id + "/memberships?accountId=" + id));
    }

    private static org.springframework.test.web.servlet.request.RequestPostProcessor principal(java.util.UUID id) {
        return org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt()
                .jwt(token -> token.subject(id.toString()).claim("sid",id.toString()));
    }

    @Test
    @WithMockUser
    void defaultVersionHasNoLegacyAlias() throws Exception {
        mvc.perform(post("/api/v1/auth/login").contentType("application/json").content("{}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void browserCorsFollowsConfiguredPrefix() throws Exception {
        mvc.perform(options(apiVersion.path("/auth/login"))
                .header("Origin","https://app.example.com")
                .header("Access-Control-Request-Method","POST")
                .header("Access-Control-Request-Headers","Content-Type,X-Auth-Transport"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin","https://app.example.com"))
                .andExpect(header().string("Access-Control-Allow-Credentials","true"));
        mvc.perform(options("/api/v1/auth/login")
                .header("Origin","https://app.example.com")
                .header("Access-Control-Request-Method","POST"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Credentials"));
    }

    @Test
    void jwksDiscoveryPathRemainsFixed() throws Exception {
        mvc.perform(get("/.well-known/jwks.json")).andExpect(status().isOk());
    }
}

