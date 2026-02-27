package com.unidocs.auth.organization.employee;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import com.unidocs.auth.authentication.api.TokenResponse;
@Tag(name = "Employees", description = "Administrator-managed employee credentials and login.")
@RestController
@RequestMapping("${api.version.base-path}")
public class EmployeeController {
    private final EmployeeService employees;
    private final com.unidocs.auth.authentication.browser.BrowserRefreshTransport browserRefresh;
    public EmployeeController(EmployeeService employees, com.unidocs.auth.authentication.browser.BrowserRefreshTransport browserRefresh) { this.employees=employees; this.browserRefresh=browserRefresh; }
    @Operation(summary = "Create an employee account", description = "An authorized organization administrator provisions an employee and returns temporary credentials.")
    @ApiResponse(responseCode = "201", description = "Employee account created; temporary credentials are returned.", useReturnTypeSchema = true)
    @PostMapping("/organizations/{org}/employees")
    @org.springframework.security.access.prepost.PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    ResponseEntity<EmployeeRequests.Credentials> create(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID org,@Valid @RequestBody EmployeeRequests.Create request) {
        return ResponseEntity.status(201).header("Cache-Control","no-store").body(employees.create(sid(jwt),subject(jwt),org,request));
    }
    @Operation(summary = "Reset temporary employee credentials", description = "An authorized administrator verifies password proof and issues new temporary credentials.")
    @PostMapping("/organizations/{org}/employees/{account}/temporary-credentials")
    @org.springframework.security.access.prepost.PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    ResponseEntity<EmployeeRequests.Credentials> reset(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID org,@PathVariable UUID account,@Valid @RequestBody EmployeeRequests.Reset request) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(employees.reset(sid(jwt),subject(jwt),org,account,request));
    }
    @Operation(summary = "Log in as an employee", description = "Authenticates an employee username and password. A new password is required when temporary credentials must be changed.")
    @PostMapping("/auth/employee-login")
    ResponseEntity<TokenResponse> login(@Valid @RequestBody EmployeeRequests.Login request,HttpServletRequest servletRequest,jakarta.servlet.http.HttpServletResponse servletResponse) {
        boolean browser = browserRefresh.validate(servletRequest);
        return browserRefresh.response(browser, employees.login(request,servletRequest.getRemoteAddr()), servletResponse);
    }
    private static UUID sid(Jwt jwt) { return UUID.fromString(jwt.getClaimAsString("sid")); }
    private static UUID subject(Jwt jwt) { return UUID.fromString(jwt.getSubject()); }
}
