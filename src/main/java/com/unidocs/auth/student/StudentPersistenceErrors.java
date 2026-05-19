package com.unidocs.auth.student;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(basePackageClasses=StudentWorkspaceController.class,
        assignableTypes={com.unidocs.auth.authorization.controlplane.StudentStaffReconciliationController.class,
                com.unidocs.auth.registration.student.StudentAdmissionController.class})
@Order(Ordered.HIGHEST_PRECEDENCE)
public class StudentPersistenceErrors {
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ProblemDetail> conflict(DataIntegrityViolationException failure) {
        ProblemDetail problem=ProblemDetail.forStatus(HttpStatus.CONFLICT);problem.setProperty("code","STUDENT_STATE_CONFLICT");
        return ResponseEntity.status(HttpStatus.CONFLICT).header("Cache-Control","no-store").body(problem);
    }
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ProblemDetail> unavailable(DataAccessException failure) {
        ProblemDetail problem=ProblemDetail.forStatus(HttpStatus.SERVICE_UNAVAILABLE);problem.setProperty("code","CURRENT_STUDENT_AUTHORITY_UNAVAILABLE");
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).header("Cache-Control","no-store").header("Retry-After","1").body(problem);
    }
}
