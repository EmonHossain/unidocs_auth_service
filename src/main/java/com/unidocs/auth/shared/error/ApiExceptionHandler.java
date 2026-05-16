package com.unidocs.auth.shared.error;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.unidocs.auth.shared.config.RequestCorrelationFilter;

@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {
    private static final Logger LOG = LoggerFactory.getLogger(ApiExceptionHandler.class);
    private final com.unidocs.auth.shared.config.ApiVersionProperties apiVersion;

    @ExceptionHandler(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class)
    ResponseEntity<Object> handleOperationAuthorizationFailure(com.unidocs.auth.authorization.application.OperationAuthorizationFailure exception, WebRequest request) {
        HttpHeaders headers = new HttpHeaders();
        headers.setCacheControl("no-store");
        if (exception.status() == HttpStatus.SERVICE_UNAVAILABLE) headers.set("Retry-After", "1");
        return handleExceptionInternal(exception, null, headers, exception.status(), request);
    }

    public ApiExceptionHandler(com.unidocs.auth.shared.config.ApiVersionProperties apiVersion) {
        this.apiVersion=apiVersion;
    }

    @ExceptionHandler(com.unidocs.auth.account.lifecycle.LifecycleFailure.class)
    ResponseEntity<Object> handleLifecycle(com.unidocs.auth.account.lifecycle.LifecycleFailure exception, WebRequest request) {
        ProblemDetail problem=ProblemDetail.forStatus(exception.status());
        problem.setProperty("code",exception.code());
        if("ACCOUNT_SELECTION_REQUIRED".equals(exception.code())) problem.setProperty("selectionUrl",apiVersion.path("/me/account-removal/options"));
        return ResponseEntity.status(exception.status()).body(problem);
    }
    @ExceptionHandler(com.unidocs.auth.group.application.GroupFailure.class)
    ResponseEntity<Object> handleGroupFailure(com.unidocs.auth.group.application.GroupFailure exception, WebRequest request) {
        return handleExceptionInternal(exception, null, HttpHeaders.EMPTY, exception.status(), request);
    }

    @ExceptionHandler(com.unidocs.auth.organization.application.OrganizationFailure.class)
    ResponseEntity<Object> handleOrganizationFailure(com.unidocs.auth.organization.application.OrganizationFailure exception, WebRequest request) {
        return handleExceptionInternal(exception, null, HttpHeaders.EMPTY, exception.status(), request);
    }

    @ExceptionHandler(com.unidocs.auth.account.application.AccountAccessDenied.class)
    ResponseEntity<Object> handleAccountAccessDenied(com.unidocs.auth.account.application.AccountAccessDenied exception, WebRequest request) {
        return handleExceptionInternal(exception, null, HttpHeaders.EMPTY, HttpStatus.FORBIDDEN, request);
    }

    @ExceptionHandler(com.unidocs.auth.authentication.application.AuthenticationFailure.class)
    ResponseEntity<Object> handleAuthenticationFailure(
            com.unidocs.auth.authentication.application.AuthenticationFailure exception, WebRequest request) {
        return handleExceptionInternal(exception, null, HttpHeaders.EMPTY, HttpStatus.UNAUTHORIZED, request);
    }

    @ExceptionHandler(org.springframework.security.core.AuthenticationException.class)
    ResponseEntity<Object> handleMethodAuthenticationFailure(Exception exception, WebRequest request) {
        return handleExceptionInternal(exception, null, HttpHeaders.EMPTY, HttpStatus.UNAUTHORIZED, request);
    }

    @ExceptionHandler(org.springframework.security.access.AccessDeniedException.class)
    ResponseEntity<Object> handleMethodAccessDenied(Exception exception, WebRequest request) {
        return handleExceptionInternal(exception, null, HttpHeaders.EMPTY,
                HttpStatus.FORBIDDEN, request);
    }

    @ExceptionHandler(com.unidocs.auth.registration.application.RegistrationException.class)
    ResponseEntity<Object> handleRegistrationException(
            com.unidocs.auth.registration.application.RegistrationException exception, WebRequest request) {
        return handleExceptionInternal(exception, null, HttpHeaders.EMPTY, exception.status(), request);
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception exception, Object body,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status,
                "The request could not be processed.");
        problem.setProperty("requestId", request.getAttribute(RequestCorrelationFilter.REQUEST_ID,
                WebRequest.SCOPE_REQUEST));
        return super.handleExceptionInternal(exception, problem, headers, status, request);
    }

    @ExceptionHandler(com.unidocs.auth.authentication.browser.BrowserRefreshDenied.class)
    ResponseEntity<Object> handleBrowserRefreshDenied(Exception exception, WebRequest request) {
        return handleExceptionInternal(exception, null, HttpHeaders.EMPTY, HttpStatus.FORBIDDEN, request);
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<Object> handleUnexpectedException(Exception exception, WebRequest request) {
        // Exception messages, stack traces and request values may contain secrets.
        LOG.error("Unexpected request failure; exceptionType={}", exception.getClass().getSimpleName());
        return handleExceptionInternal(exception, null, HttpHeaders.EMPTY,
                HttpStatus.INTERNAL_SERVER_ERROR, request);
    }
}
