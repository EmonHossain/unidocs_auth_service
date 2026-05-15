package com.unidocs.auth.shared.config;

import java.util.UUID;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.MDC;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/** Diagnostic identity only; never consulted by authentication or authorization. */
public final class TrustedRequestContext {
    public static final String USER_ID = "user.id";
    public static final String TENANT_ID = "labels.tenant_id";
    private static final String PRINCIPAL = TrustedRequestContext.class.getName() + ".principal";
    private static final String ORGANIZATION = TrustedRequestContext.class.getName() + ".organization";

    private TrustedRequestContext() { }

    public static void authenticatedPrincipal(HttpServletRequest request, UUID principal) {
        request.setAttribute(PRINCIPAL, principal);
        MDC.put(USER_ID, principal.toString());
    }

    /** Call only after the use case establishes current authority for this organization. */
    public static void authorizedOrganization(UUID organization) {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            HttpServletRequest request = attributes.getRequest();
            if (principal(request) != null) {
                request.setAttribute(ORGANIZATION, organization);
                MDC.put(TENANT_ID, organization.toString());
            }
        }
    }

    public static UUID principal(HttpServletRequest request) {
        return request.getAttribute(PRINCIPAL) instanceof UUID principal ? principal : null;
    }

    public static UUID organization(HttpServletRequest request) {
        return request.getAttribute(ORGANIZATION) instanceof UUID organization ? organization : null;
    }

    static void clear(HttpServletRequest request) {
        request.removeAttribute(PRINCIPAL);
        request.removeAttribute(ORGANIZATION);
        MDC.remove(USER_ID);
        MDC.remove(TENANT_ID);
    }

    public static void restoreMdc(String key, String previous) {
        if (previous == null) MDC.remove(key);
        else MDC.put(key, previous);
    }
}
