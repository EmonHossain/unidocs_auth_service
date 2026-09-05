package com.unidocs.auth.registration;

import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.authentication.api.*;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.authentication.browser.BrowserRefreshTransport;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.application.RegistrationService;
import com.unidocs.auth.registration.application.RegistrationProvisioningService;
import com.unidocs.auth.session.domain.RefreshSecret;
import jakarta.servlet.http.Cookie;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = "auth.browser-refresh.allowed-origins=https://drive.example")
@AutoConfigureMockMvc
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
class BrowserRefreshIntegrationTests extends MySqlIntegrationTest {
    private static final String ORIGIN = "https://drive.example";
    private static final String PASSWORD = "browser-password-long";
    @Autowired MockMvc mvc;
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired org.springframework.context.ApplicationContext application;
    @Autowired com.unidocs.auth.organization.application.OrganizationService organizations;
    @Autowired com.unidocs.auth.organization.employee.EmployeeService employees;
    private String email;

    @BeforeEach void provision() {
        email = UUID.randomUUID() + "@example.com";
        RegistrationResponse pending = registrations.register(new RegistrationRequest("Browser User", email, PASSWORD));
        String code = delivery.tokens.get(pending.id());
        registrations.verify(pending.id(), new VerificationRequest(code));
        provisioning.complete(pending.id(), new RegistrationCompletionRequest(code));
    }
    private String loginBody() { return "{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"; }
    private MvcResult browserLogin() throws Exception {
        return mvc.perform(post("/api/v1/auth/login").header("Origin", ORIGIN)
                .header(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE)
                .contentType("application/json").content(loginBody()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.refreshToken").isEmpty())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andReturn();
    }
    private Cookie refreshCookie(MvcResult result) {
        String header = result.getResponse().getHeader("Set-Cookie");
        assertThat(header).contains("Secure", "HttpOnly", "SameSite=Strict", "Path=/").doesNotContain("Domain=", "Max-Age=");
        return new Cookie(BrowserRefreshTransport.COOKIE, header.substring(header.indexOf('=') + 1, header.indexOf(';')));
    }
    private String accessToken(MvcResult result) throws java.io.UnsupportedEncodingException {
        return com.jayway.jsonpath.JsonPath.read(result.getResponse().getContentAsString(), "$.accessToken");
    }

    @Test void browserRotationAndProvenReplayRevokeFamilyWithoutJsonSecret() throws Exception {
        MvcResult login = browserLogin();
        Cookie first = refreshCookie(login);
        MvcResult rotated = mvc.perform(post("/api/v1/auth/refresh").header("Origin", ORIGIN)
                        .header(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE).cookie(first))
                .andExpect(status().isOk()).andExpect(jsonPath("$.refreshToken").isEmpty()).andReturn();
        Cookie second = refreshCookie(rotated);
        assertThat(second.getValue()).isNotEqualTo(first.getValue());
        assertThat(rotated.getResponse().getContentAsString()).doesNotContain(first.getValue(), second.getValue());
        assertThat(jdbc.queryForObject("SELECT secret_hash FROM session_refresh_token WHERE used_at IS NULL", String.class))
                .isEqualTo(RefreshSecret.parse(second.getValue()).hash());
        mvc.perform(post("/api/v1/auth/refresh").header("Origin", ORIGIN)
                        .header(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE).cookie(first))
                .andExpect(status().isUnauthorized()).andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("Max-Age=0")));
        mvc.perform(post("/api/v1/auth/refresh").header("Origin", ORIGIN)
                        .header(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE).cookie(second))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/me").header("Authorization", "Bearer " + accessToken(rotated)))
                .andExpect(status().isUnauthorized());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='REFRESH_REPLAY'", Integer.class)).isEqualTo(1);
    }

    @Test void originAndHeaderGuardsPreventLoginCsrfBeforeSessionCreation() throws Exception {
        for (String origin : new String[]{"https://evil.example", "null", "https://drive.example.evil"}) {
            mvc.perform(post("/api/v1/auth/login").header("Origin", origin)
                    .header(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE)
                    .contentType("application/json").content(loginBody())).andExpect(status().isForbidden());
        }
        mvc.perform(post("/api/v1/auth/login").header(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE)
                .contentType("application/json").content(loginBody())).andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/auth/login").header("Origin", ORIGIN).header(BrowserRefreshTransport.HEADER, "unknown")
                .contentType("application/json").content(loginBody())).andExpect(status().isForbidden());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_session", Integer.class)).isZero();
    }

    @Test void cookieAloneAndAmbiguousBodyCannotRotateWhileApiBodyRemainsSupported() throws Exception {
        TokenResponse token = authentication.login(new LoginRequest(email, PASSWORD));
        Cookie cookie = new Cookie(BrowserRefreshTransport.COOKIE, token.refreshToken());
        mvc.perform(post("/api/v1/auth/refresh").header("Origin", ORIGIN).cookie(cookie))
                .andExpect(status().isUnauthorized());
        String body = "{\"refreshToken\":\"" + token.refreshToken() + "\"}";
        mvc.perform(post("/api/v1/auth/refresh").header("Origin", ORIGIN)
                .header(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE).cookie(cookie)
                .contentType("application/json").content(body)).andExpect(status().isUnauthorized());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_refresh_token WHERE used_at IS NOT NULL", Integer.class)).isZero();
        mvc.perform(post("/api/v1/auth/refresh").cookie(new Cookie(BrowserRefreshTransport.COOKIE, "invalid"))
                .contentType("application/json").content(body)).andExpect(status().isOk())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty()).andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test void duplicateCookiesAndWrongSecretsDoNotRevokeLegitimateSessions() throws Exception {
        TokenResponse token = authentication.login(new LoginRequest(email, PASSWORD));
        Cookie cookie = new Cookie(BrowserRefreshTransport.COOKIE, token.refreshToken());
        mvc.perform(post("/api/v1/auth/refresh").header("Origin", ORIGIN)
                .header(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE).cookie(cookie, cookie))
                .andExpect(status().isUnauthorized());
        RefreshSecret parsed = RefreshSecret.parse(token.refreshToken());
        String guess = new RefreshSecret(parsed.id(), RefreshSecret.create().secret()).value();
        mvc.perform(post("/api/v1/auth/refresh").header("Origin", ORIGIN)
                .header(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE)
                .cookie(new Cookie(BrowserRefreshTransport.COOKIE, guess)))
                .andExpect(status().isUnauthorized());
        assertThat(jdbc.queryForObject("SELECT status FROM user_session", String.class)).isEqualTo("ACTIVE");
        authentication.refresh(new RefreshRequest(token.refreshToken()));
    }

    @Test void browserLogoutClearsCookieAndRevokesOnlyCurrentDevice() throws Exception {
        MvcResult browser = browserLogin();
        Cookie cookie = refreshCookie(browser);
        TokenResponse other = authentication.login(new LoginRequest(email, PASSWORD));
        mvc.perform(post("/api/v1/auth/logout").header("Authorization", "Bearer " + accessToken(browser))
                .header("Origin", ORIGIN).header(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE).cookie(cookie))
                .andExpect(status().isNoContent()).andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("Max-Age=0")));
        assertThatThrownBy(() -> authentication.refresh(new RefreshRequest(cookie.getValue())))
                .isInstanceOf(com.unidocs.auth.authentication.application.AuthenticationFailure.class);
        authentication.refresh(new RefreshRequest(other.refreshToken()));
    }

    @Test void browserLogoutAllRequiresBearerAndClearsCurrentCookie() throws Exception {
        mvc.perform(post("/api/v1/auth/logout-all")).andExpect(status().isUnauthorized());
        MvcResult browser = browserLogin();
        TokenResponse other = authentication.login(new LoginRequest(email, PASSWORD));
        mvc.perform(post("/api/v1/auth/logout-all").header("Authorization", "Bearer " + accessToken(browser))
                .header("Origin", ORIGIN).header(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE))
                .andExpect(status().isNoContent()).andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("Max-Age=0")));
        assertThatThrownBy(() -> authentication.refresh(new RefreshRequest(other.refreshToken())))
                .isInstanceOf(com.unidocs.auth.authentication.application.AuthenticationFailure.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_session WHERE status='ACTIVE'", Integer.class)).isZero();
    }

@Test void employeeActivationAndAccountLoginUseProtectedCookieTransport() throws Exception {
        TokenResponse owner = authentication.login(new LoginRequest(email, PASSWORD));
        com.unidocs.auth.organization.api.OrganizationResponse org = organizations.create(owner.sessionId(), owner.loginAccountId(),
                new com.unidocs.auth.organization.api.OrganizationRequest(owner.loginAccountId(), UUID.randomUUID(), "Browser company",
                        "browser-" + UUID.randomUUID(), com.unidocs.auth.organization.domain.Organization.Type.COMPANY));
        owner=ProfessionalFixture.administrator(application,owner,PASSWORD,org.id());
        com.unidocs.auth.organization.employee.EmployeeRequests.Credentials employee = employees.create(owner.sessionId(), owner.loginAccountId(), org.id(),
                new com.unidocs.auth.organization.employee.EmployeeRequests.Create(owner.loginAccountId(), UUID.randomUUID(), "Browser employee"));
        String body = "{\"username\":\"" + employee.username() + "\",\"password\":\"" + employee.temporaryPassword()
                + "\",\"newPassword\":\"employee-browser-password\"}";
        mvc.perform(post("/api/v1/auth/employee-login").header("Origin", "https://evil.example")
                .header(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE).contentType("application/json").content(body))
                .andExpect(status().isForbidden());
        assertThat(jdbc.queryForObject("SELECT status FROM employee_activation", String.class)).isEqualTo("PENDING");
        MvcResult activated = mvc.perform(post("/api/v1/auth/employee-login").header("Origin", ORIGIN)
                .header(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE).contentType("application/json").content(body))
                .andExpect(status().isOk()).andExpect(jsonPath("$.refreshToken").isEmpty()).andReturn();
        refreshCookie(activated);
        MvcResult account = mvc.perform(post("/api/v1/auth/accounts/" + employee.accountId() + "/login").header("Origin", ORIGIN)
                .header(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE).contentType("application/json")
                .content("{\"password\":\"employee-browser-password\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.refreshToken").isEmpty()).andReturn();
        Cookie cookie = refreshCookie(account);
        mvc.perform(post("/api/v1/auth/refresh").header("Origin", ORIGIN)
                .header(BrowserRefreshTransport.HEADER, BrowserRefreshTransport.MODE).cookie(cookie))
                .andExpect(status().isOk()).andExpect(jsonPath("$.refreshToken").isEmpty());
    }

    @Test void corsPreflightAllowsOnlyConfiguredOriginAndExplicitBrowserHeader() throws Exception {
        mvc.perform(options("/api/v1/auth/refresh").header("Origin", ORIGIN)
                .header("Access-Control-Request-Method", "POST")
                .header("Access-Control-Request-Headers", "X-Auth-Transport,Content-Type"))
                .andExpect(status().isOk()).andExpect(header().string("Access-Control-Allow-Origin", ORIGIN))
                .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
        mvc.perform(options("/api/v1/auth/refresh").header("Origin", "https://evil.example")
                .header("Access-Control-Request-Method", "POST")).andExpect(status().isForbidden());
    }
}
