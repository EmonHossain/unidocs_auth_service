package com.unidocs.auth.group.personal;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class PersonalAccountDepartureTests {
    @Test void departureCannotPartiallyAutocommitOutsideExistingAccountTransaction(){
        JdbcTemplate jdbc=mock(JdbcTemplate.class);PersonalAccountDeparture departure=new PersonalAccountDeparture(jdbc);
        UUID account=UUID.randomUUID();
        assertThatThrownBy(()->departure.assertDepartureAllowed(account,Instant.now(),false)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(()->departure.depart(account,Instant.now(),account,UUID.randomUUID(),null)).isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(jdbc);
    }
}
