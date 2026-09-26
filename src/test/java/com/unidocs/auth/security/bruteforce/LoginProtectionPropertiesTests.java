package com.unidocs.auth.security.bruteforce;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class LoginProtectionPropertiesTests {
    @Test
    void validBoundedSettingsAreRetained() {
        LoginProtectionProperties properties = new LoginProtectionProperties(true,"auth:login:v1",Duration.ofMinutes(15),50,10,5);
        assertThat(properties.enabled()).isTrue();
        assertThat(properties.window()).isEqualTo(Duration.ofMinutes(15));
    }

    @Test
    void namespacesCannotSupplyHashTagsWildcardsOrUnboundedText() {
        for (String prefix : new String[]{"", "auth:{custom}", "auth:*", "a".repeat(101)}) {
            assertThatThrownBy(() -> new LoginProtectionProperties(true,prefix,Duration.ofMinutes(15),50,10,5)).isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> new LoginProtectionProperties(true,null,Duration.ofMinutes(15),50,10,5)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void windowsAndLimitsMustRemainBounded() {
        for (Duration window : new Duration[]{Duration.ZERO,Duration.ofMillis(999),Duration.ofHours(25)}) {
            assertThatThrownBy(() -> new LoginProtectionProperties(true,"auth",window,50,10,5)).isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> new LoginProtectionProperties(true,"auth",null,50,10,5)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LoginProtectionProperties(true,"auth",Duration.ofMinutes(15),0,10,5)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LoginProtectionProperties(true,"auth",Duration.ofMinutes(15),50,-1,5)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LoginProtectionProperties(true,"auth",Duration.ofMinutes(15),50,10,1000001)).isInstanceOf(IllegalArgumentException.class);
    }
}
