package com.unidocs.auth.authorization.api;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(assignableTypes = OperationAuthorizationController.class)
@Order(Ordered.HIGHEST_PRECEDENCE)
public class OperationPersistenceErrors {
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ProblemDetail> unavailable(DataAccessException failure) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.SERVICE_UNAVAILABLE);
        problem.setProperty("code", "CURRENT_AUTHORITY_UNAVAILABLE");
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).header("Cache-Control", "no-store")
                .header("Retry-After", "1").body(problem);
    }
}
