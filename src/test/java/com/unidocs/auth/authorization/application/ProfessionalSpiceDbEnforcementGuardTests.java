package com.unidocs.auth.authorization.application;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;

class ProfessionalSpiceDbEnforcementGuardTests {
    private final ApplicationContextRunner contexts = new ApplicationContextRunner()
            .withUserConfiguration(ProfessionalSpiceDbEnforcementGuard.class);

    /**
     * Content switches cannot silently become a SQL-only path when their graph bean is absent.
     * @param property independently selected content slice
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"workspace-read-enabled", "content-enabled"})
    void selectedContentRequiresTheCanaryAtStartup(String property) {
        ApplicationContextRunner content = new ApplicationContextRunner()
                .withUserConfiguration(ProfessionalSpiceDbWorkspaceReadGuard.class, ProfessionalSpiceDbContentGuard.class);
        content.withPropertyValues("auth.spicedb.canary." + property + "=true")
                .run(context -> assertNotNull(context.getStartupFailure()));
        content.withPropertyValues("auth.spicedb.canary." + property + "=true")
                .withUserConfiguration(CanaryStub.class).run(context -> assertNull(context.getStartupFailure()));
        content.run(context -> assertNull(context.getStartupFailure()));
    }

    @Test
    void enforcementCannotStartWithoutTheCanary() {
        contexts.withPropertyValues("auth.spicedb.canary.enforcement-enabled=true")
                .run(context -> assertNotNull(context.getStartupFailure()));
    }

    @Test
    void disabledEnforcementDoesNotRequireTheCanary() {
        contexts.withPropertyValues("auth.spicedb.canary.enforcement-enabled=false")
                .run(context -> assertNull(context.getStartupFailure()));
    }

    @Test
    void enforcementCanStartWithTheCanary() {
        contexts.withPropertyValues("auth.spicedb.canary.enforcement-enabled=true")
                .withUserConfiguration(CanaryStub.class)
                .run(context -> assertNull(context.getStartupFailure()));
    }

    @Configuration(proxyBeanMethods = false)
    static class CanaryStub {
        @Bean
        ProfessionalSpiceDbCanary canary() {
            return mock(ProfessionalSpiceDbCanary.class);
        }
    }
}
