package com.unidocs.auth.authorization.controlplane;

import com.unidocs.auth.group.personal.PersonalGroupController;
import com.unidocs.auth.group.personal.PersonalGroupInternalController;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

/** Bounded public errors never expose SQL, proof material or infrastructure diagnostics. */
@RestControllerAdvice(assignableTypes={DeveloperCatalogController.class,ProfessionalReconciliationController.class,com.unidocs.auth.organization.professional.ProfessionalPolicyController.class,PersonalGroupController.class,PersonalGroupInternalController.class})
@Order(Ordered.HIGHEST_PRECEDENCE)
public class ControlPlanePersistenceErrors {
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ProblemDetail> conflict(DataIntegrityViolationException exception){
        return ResponseEntity.status(HttpStatus.CONFLICT).header("Cache-Control","no-store").body(ProblemDetail.forStatus(HttpStatus.CONFLICT));
    }
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ProblemDetail> unavailable(DataAccessException exception){
        ProblemDetail problem=ProblemDetail.forStatus(HttpStatus.SERVICE_UNAVAILABLE);
        problem.setProperty("code","CURRENT_AUTHORITY_UNAVAILABLE");
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).header("Cache-Control","no-store").header("Retry-After","1").body(problem);
    }
}
