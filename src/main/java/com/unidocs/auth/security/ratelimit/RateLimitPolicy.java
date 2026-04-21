package com.unidocs.auth.security.ratelimit;
import jakarta.servlet.http.HttpServletRequest;
import com.unidocs.auth.shared.config.ApiVersionProperties;
public enum RateLimitPolicy {
    REGISTRATION, LOGIN, REFRESH, FORGOT_PASSWORD, RESET_PASSWORD, VERIFICATION;
    public static RateLimitPolicy resolve(HttpServletRequest request) {
        return resolve(request, ApiVersionProperties.DEFAULT_BASE_PATH);
    }
    public static RateLimitPolicy resolve(HttpServletRequest request, String basePath) {
        if (!"POST".equals(request.getMethod())) return null;
        String path = request.getServletPath();
        if (path == null || path.isEmpty()) {
            path = request.getRequestURI().substring(request.getContextPath().length());
            try { path = org.springframework.web.util.UriUtils.decode(path, java.nio.charset.StandardCharsets.UTF_8); }
            catch (IllegalArgumentException malformed) { return null; }
        } else if (request.getPathInfo() != null) {
            path += request.getPathInfo();
        }
        if (!path.startsWith(basePath + "/")) return null;
        path = path.substring(basePath.length());
        return switch (path) {
            case "/registrations" -> REGISTRATION;
            case "/auth/login", "/auth/employee-login" -> LOGIN;
            case "/auth/refresh" -> REFRESH;
            case "/auth/forgot-password", "/auth/employee-forgot-password" -> FORGOT_PASSWORD;
            case "/auth/reset-password", "/auth/employee-reset-password" -> RESET_PASSWORD;
            default -> dynamic(path);
        };
    }
    private static RateLimitPolicy dynamic(String path) {
        if (path.matches("/auth/accounts/[^/]+/login")) return LOGIN;
        if (path.matches("/registrations/[^/]+/(verify|complete)")) return VERIFICATION;
        if (path.matches("/institutes/[^/]+/student-admissions")) return REGISTRATION;
        if (path.matches("/institutes/[^/]+/student-admissions/[^/]+/verify")) return VERIFICATION;
        return null;
    }
}

