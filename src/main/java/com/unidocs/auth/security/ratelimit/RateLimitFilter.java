package com.unidocs.auth.security.ratelimit;
import java.io.IOException;
import com.unidocs.auth.shared.config.ApiVersionProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;
import com.unidocs.auth.security.config.SecurityProblemWriter;
public class RateLimitFilter extends OncePerRequestFilter {
    private final ApiVersionProperties api;
    private final RateLimitService limits;
    private final SecurityProblemWriter problems;
    public RateLimitFilter(RateLimitService limits, SecurityProblemWriter problems) {
        this(limits, problems, new ApiVersionProperties(null));
    }
    public RateLimitFilter(RateLimitService limits, SecurityProblemWriter problems, ApiVersionProperties api) {
        this.api = api;
        this.limits = limits; this.problems = problems;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        RateLimitPolicy policy = RateLimitPolicy.resolve(request, api.basePath());
        if (policy != null) {
            try { limits.check(policy, request); }
            catch (RateLimitException blocked) {
                response.setHeader("Retry-After", Long.toString(blocked.retryAfterSeconds()));
                response.setHeader("Cache-Control", "no-store");
                problems.write(request, response, HttpStatus.TOO_MANY_REQUESTS, "Too many requests.");
                return;
            } catch (RateLimitUnavailableException unavailable) {
                response.setHeader("Cache-Control", "no-store");
                problems.write(request, response, HttpStatus.SERVICE_UNAVAILABLE, "Request admission is unavailable.");
                return;
            }
        }
        chain.doFilter(request, response);
    }
}

