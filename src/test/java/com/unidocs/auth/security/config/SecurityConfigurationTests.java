package com.unidocs.auth.security.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.unidocs.auth.shared.config.RequestCorrelationFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest
@Import({SecurityConfiguration.class, SecurityProblemWriter.class, RequestCorrelationFilter.class})
class SecurityConfigurationTests {
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.authorization.application.OperationAuthorizationService operationAuthorization;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.authorization.controlplane.DeveloperCatalogService developerCatalog;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.authorization.controlplane.DeveloperInspectionService developerInspection;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.authorization.controlplane.DeveloperOperatorAuthService developerOperatorAuth;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.authorization.controlplane.DeveloperOperatorRecoveryService developerOperatorRecovery;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.authorization.controlplane.ProfessionalReconciliationService professionalReconciliation;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.authorization.controlplane.StudentStaffReconciliationService studentStaffReconciliation;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.organization.professional.ProfessionalPolicyService professionalPolicy;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.student.StudentPlatformService studentPlatform;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.student.StudentProvisioningService studentProvisioning;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.student.StudentWorkspaceService studentWorkspace;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.student.StudentReportEvidenceService studentReportEvidence;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.group.personal.PersonalGroupService personalGroups;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.group.personal.PersonalGroupClosureService personalGroupClosures;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.authorization.application.InternalAuthorizationService internalAuthorization;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.authentication.browser.BrowserRefreshTransport browserRefresh;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.credential.recovery.email.EmailPasswordRecoveryService emailRecovery;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.organization.employee.recovery.EmployeeRecoveryService employeeRecovery;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.organization.employee.EmployeeService employees;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.registration.student.StudentAdmissionService studentAdmissions;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.group.application.GroupRuleService groupRules;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.group.application.AcademicEnrollmentService enrollments;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.group.application.GroupInvitationService groupInvitations;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.group.application.GroupJoinService groupJoins;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.group.application.GroupMembershipService groupMemberships;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.account.lifecycle.AccountLifecycleService lifecycle;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.group.application.GroupService groups;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.organization.application.OrganizationAccountService organizationAccounts;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.organization.application.InvitationService invitations;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.organization.application.OrganizationService organizations;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.account.application.LinkedAccountService accounts;
    @org.springframework.test.context.bean.override.mockito.MockitoBean(name="jwtDecoder")
    org.springframework.security.oauth2.jwt.JwtDecoder jwtDecoder;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.authentication.application.AuthenticationService authentication;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.security.jwt.JwtKeyRing keys;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.registration.application.RegistrationService registrations;
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.unidocs.auth.registration.application.RegistrationProvisioningService provisioning;
    @Autowired MockMvc mvc;
    @Autowired com.unidocs.auth.shared.config.ApiVersionProperties apiVersion;

    @Test
    void clientIdentityAndBasicCredentialsCannotAuthenticate() throws Exception {
        MvcResult result = mvc.perform(get(apiVersion.path("/me")).header("X-User-Id", "attacker")
                        .header("Authorization", "Basic dXNlcjpwYXNzd29yZA=="))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.requestId").exists()).andExpect(header().doesNotExist("WWW-Authenticate"))
                .andReturn();
        assertThat(result.getRequest().getSession(false)).isNull();
        assertThat(result.getResponse().getContentAsString()).doesNotContain("attacker", "dXNlcj", "password");
    }

    @Test
    void documentationIsClosedByDefault() throws Exception {
        for (String path : java.util.List.of("/swagger-ui.html", "/swagger-ui/index.html", "/v3/api-docs", "/v3/api-docs.yaml")) {
            assertThat(mvc.perform(get(path)).andReturn().getResponse().getStatus()).isIn(401, 403, 404);
        }
    }

    @Test
    @WithMockUser
    void documentationCannotBeAccessedWhenDisabled() throws Exception {
        assertThat(mvc.perform(get("/v3/api-docs")).andReturn().getResponse().getStatus()).isIn(403, 404);
    }

    @Test
    void writesAndLoginRemainClosed() throws Exception {
        mvc.perform(post(apiVersion.path("/auth/login"))).andExpect(status().isBadRequest());
        mvc.perform(post("/actuator/health")).andExpect(status().isUnauthorized());
        mvc.perform(get("/login")).andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser
    void authenticatedButForbiddenIs403() throws Exception {
        mvc.perform(get("/actuator/prometheus")).andExpect(status().isForbidden());
        mvc.perform(get(apiVersion.path("/forbidden"))).andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.status").value(403));
    }

    @Test
    @WithMockUser
    void methodDenialIsAProblemResponseInsteadOfAnUnexpectedFailure() throws Exception {
        mvc.perform(get(apiVersion.path("/me")))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.status").value(403));
        org.mockito.Mockito.verifyNoInteractions(authentication);
    }
    @Test
    void organizationRecoveryRequiresAuthentication() throws Exception {
        String organization = "00000000-0000-0000-0000-000000000001";
        String request = "00000000-0000-0000-0000-000000000002";
        mvc.perform(get(apiVersion.path("/organizations/") + organization + "/password-recovery-requests")
                        .param("adminAccountId", request)).andExpect(status().isUnauthorized());
        mvc.perform(post(apiVersion.path("/organizations/") + organization + "/password-recovery-requests/" + request + "/reset")
                        .contentType("application/json").content("{}"))
                .andExpect(status().isUnauthorized());
    }
    @Autowired
    @org.springframework.beans.factory.annotation.Qualifier("requestMappingHandlerMapping")
    org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping mappings;

    @Test
    void everyApplicationControllerIsRegistered() throws Exception {
        org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider scanner=
                new org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter((reader,factory)->reader.getClassMetadata().getClassName().endsWith("Controller")
                && !reader.getClassMetadata().getClassName().contains("$"));
        java.util.Set<Class<?>> registered=new java.util.HashSet<>();
        for(org.springframework.web.method.HandlerMethod handler : mappings.getHandlerMethods().values()) {
            registered.add(handler.getBeanType());
        }
        java.util.Set<org.springframework.beans.factory.config.BeanDefinition> controllers=scanner.findCandidateComponents("com.unidocs.auth");
        assertThat(controllers).isNotEmpty();
        for(org.springframework.beans.factory.config.BeanDefinition definition : controllers) {
            Class<?> controller=Class.forName(definition.getBeanClassName());
            assertThat(org.springframework.core.annotation.AnnotatedElementUtils.hasAnnotation(controller,
                    org.springframework.web.bind.annotation.RestController.class))
                    .as("REST controller registration for %s",controller.getName()).isTrue();
            assertThat(registered).as("Mapped controller %s",controller.getName()).contains(controller);
        }
    }

    @Test
    void everyApplicationRouteUsesConfiguredBasePath() {
        int routes=0;
        for (java.util.Map.Entry<org.springframework.web.servlet.mvc.method.RequestMappingInfo,
                org.springframework.web.method.HandlerMethod> entry : mappings.getHandlerMethods().entrySet()) {
            if (!applicationController(entry.getValue())) continue;
            for (String path : entry.getKey().getPatternValues()) {
                if (path.equals("/.well-known/jwks.json")) continue;
                assertThat(path).as("Route for %s",entry.getValue()).startsWith(apiVersion.basePath()+"/");
                routes++;
            }
        }
        assertThat(routes).isPositive();
    }

    @Test
    void requestAndResponseGraphsDoNotExposePersistenceEntities() {
        for (org.springframework.web.method.HandlerMethod handler : mappings.getHandlerMethods().values()) {
            if (!applicationController(handler)) continue;
            assertDtoTypes(org.springframework.core.ResolvableType.forMethodReturnType(handler.getMethod()),new java.util.HashSet<>());
            for (org.springframework.core.MethodParameter parameter : handler.getMethodParameters()) {
                if (parameter.hasParameterAnnotation(org.springframework.web.bind.annotation.RequestBody.class)
                        || parameter.hasParameterAnnotation(org.springframework.web.bind.annotation.RequestPart.class)
                        || parameter.hasParameterAnnotation(org.springframework.web.bind.annotation.ModelAttribute.class)) {
                    assertDtoTypes(org.springframework.core.ResolvableType.forMethodParameter(parameter),new java.util.HashSet<>());
                }
            }
        }
    }

    @Test
    void entityDetectionIncludesNestedCollectionElements() {
        assertThatThrownBy(()->assertDtoTypes(org.springframework.core.ResolvableType.forClass(UnsafePage.class),new java.util.HashSet<>()))
                .isInstanceOf(AssertionError.class).hasMessageContaining("UserAccount");
    }

    @Test
    @WithMockUser
    void unversionedAndUnsupportedVersionsCannotReachLogin() throws Exception {
        for (String path : java.util.List.of("/api/auth/login","/api/v0/auth/login","/api/v2/auth/login")) {
            mvc.perform(post(path).contentType("application/json").content("{}"))
                    .andExpect(status().isForbidden());
        }
    }

    private static boolean applicationController(org.springframework.web.method.HandlerMethod handler) {
        return handler.getBeanType().getName().startsWith("com.unidocs.auth.");
    }

    private static void assertDtoTypes(org.springframework.core.ResolvableType type,java.util.Set<String> seen) {
        Class<?> value=type.resolve();
        if (value==null) return;
        assertThat(value.isAnnotationPresent(jakarta.persistence.Entity.class)
                || value.isAnnotationPresent(jakarta.persistence.Embeddable.class)
                || value.isAnnotationPresent(jakarta.persistence.MappedSuperclass.class))
                .as("API type %s must not expose persistence entities",value.getName()).isFalse();
        if (!seen.add(type.toString())) return;
        if (type.isArray()) assertDtoTypes(type.getComponentType(),seen);
        for (org.springframework.core.ResolvableType generic : type.getGenerics()) assertDtoTypes(generic,seen);
        if (!value.getName().startsWith("com.unidocs.auth.") || value.isEnum()) return;
        for (java.lang.reflect.Field field : value.getDeclaredFields()) {
            if (!java.lang.reflect.Modifier.isStatic(field.getModifiers()) && !field.isSynthetic()) {
                assertDtoTypes(org.springframework.core.ResolvableType.forType(field.getGenericType(),type),seen);
            }
        }
    }

    private record UnsafePage(java.util.List<com.unidocs.auth.account.domain.UserAccount> accounts) { }

}
