package com.unidocs.auth.shared.error;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.*;

import com.unidocs.auth.shared.config.RequestCorrelationFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(OutputCaptureExtension.class)
class ApiExceptionHandlerTests {
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.standaloneSetup(new TestController())
                .setControllerAdvice(new ApiExceptionHandler(new com.unidocs.auth.shared.config.ApiVersionProperties(null))).addFilters(new RequestCorrelationFilter()).build();
    }

    @Test
    void validationErrorsAreStructuredAndNeverEchoSubmittedValues(CapturedOutput output) throws Exception {
        mvc.perform(post("/test/input").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"\",\"secret\":\"sensitive-value\"}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.requestId").exists())
                .andExpect(content().string(not(containsString("sensitive-value"))));
        assertThat(output).doesNotContain("sensitive-value");
    }

    @Test
    void malformedJsonIsSanitized() throws Exception {
        mvc.perform(post("/test/input").contentType(MediaType.APPLICATION_JSON).content("{sensitive-value"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.status").value(400))
                .andExpect(content().string(not(containsString("sensitive-value"))));
    }

    @Test
    void unexpectedFailureDoesNotRevealExceptionMessage(CapturedOutput output) throws Exception {
        mvc.perform(get("/test/failure")).andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.status").value(500)).andExpect(jsonPath("$.requestId").exists())
                .andExpect(content().string(not(containsString("database-password"))));
        assertThat(output).doesNotContain("database-password");
    }

    @Test
    void wrongMethodKeepsHttpStatusAndAllowHeader() throws Exception {
        mvc.perform(get("/test/input")).andExpect(status().isMethodNotAllowed())
                .andExpect(header().string("Allow", "POST")).andExpect(jsonPath("$.status").value(405));
    }

    @Test
    void accountSelectionUrlTracksConfiguredPrefix() throws Exception {
        MockMvc custom=MockMvcBuilders.standaloneSetup(new TestController())
                .setControllerAdvice(new ApiExceptionHandler(new com.unidocs.auth.shared.config.ApiVersionProperties("/api/v7"))).build();
        custom.perform(get("/test/selection"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.selectionUrl").value("/api/v7/me/account-removal/options"));
    }

    @RestController
    static class TestController {
        @PostMapping("/test/input")
        void input(@Valid @RequestBody Input input) { }

        @GetMapping("/test/selection")
        void selection() { throw com.unidocs.auth.account.lifecycle.LifecycleFailure.conflict("ACCOUNT_SELECTION_REQUIRED"); }

        @GetMapping("/test/failure")
        void failure() { throw new IllegalStateException("database-password"); }
    }

    record Input(@NotBlank String name, String secret) { }
}
