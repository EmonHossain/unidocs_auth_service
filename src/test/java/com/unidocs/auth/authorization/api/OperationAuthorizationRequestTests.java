package com.unidocs.auth.authorization.api;

import java.util.UUID;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.ObjectMapper;
import static org.junit.jupiter.api.Assertions.*;

/** Wire compatibility for the optional exact-resource admission hint. */
class OperationAuthorizationRequestTests {
    /**
     * Older clients retain ordinary scoped admission; only an explicit true can request the restricted exception.
     * @param hint optional JSON field
     */
    @ParameterizedTest
    @ValueSource(strings={"",",\"exactResourceAccess\":null",",\"exactResourceAccess\":false",",\"exactResourceAccess\":true"})
    void omittedOrNullHintNeverCreatesExactResourceAdmission(String hint) throws Exception {
        UUID account=UUID.randomUUID();
        String body="{\"operationKey\":\"workspace.read\",\"accountId\":\""+account+"\",\"resourceKind\":\"WORKSPACE\""+hint+"}";
        OperationAuthorizationRequest request=new ObjectMapper().readValue(body,OperationAuthorizationRequest.class);
        assertEquals(account,request.accountId());
        assertEquals(hint.endsWith(":true"),request.exactResourceAccess());
        assertNotNull(request.exactResourceAccess());
    }
}
