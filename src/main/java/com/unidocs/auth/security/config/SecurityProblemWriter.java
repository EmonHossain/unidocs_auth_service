package com.unidocs.auth.security.config;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.stereotype.Component;

import com.unidocs.auth.shared.config.RequestCorrelationFilter;

import tools.jackson.databind.json.JsonMapper;

@Component
public class SecurityProblemWriter {
    private final JsonMapper mapper;

    public SecurityProblemWriter(JsonMapper mapper) {
        this.mapper = mapper;
    }

    public void write(HttpServletRequest request, HttpServletResponse response,
               HttpStatus status, String detail) throws IOException {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setProperty("requestId", request.getAttribute(RequestCorrelationFilter.REQUEST_ID));
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.getWriter().write(mapper.writeValueAsString(problem));
    }
}
