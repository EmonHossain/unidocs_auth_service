package com.unidocs.auth.registration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Clock;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import com.unidocs.auth.authentication.api.AccountLoginRequest;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.authorization.controlplane.DeveloperCatalogService;
import com.unidocs.auth.authorization.controlplane.ProfessionalReconciliationService;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Isolated-test provisioning uses the real developer gate and preserves the personal root account. */
final class ProfessionalFixture {
    private ProfessionalFixture() { }
    static TokenResponse administrator(ApplicationContext application,TokenResponse personal,String password,UUID organization) {
        JdbcTemplate jdbc=application.getBean(JdbcTemplate.class);
        String database=jdbc.queryForObject("SELECT DATABASE()",String.class);
        if(database==null || !database.toLowerCase(java.util.Locale.ROOT).contains("test")) throw new IllegalStateException("Professional fixtures require an isolated test database");
        Clock clock=application.getBean(Clock.class);
        Authentication prior=SecurityContextHolder.getContext().getAuthentication();
        UUID account=personal.loginAccountId();
        boolean existed=Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM iam_developer_eligibility WHERE account_id=?)",Boolean.class,bytes(account)));
        String factor=UUID.randomUUID().toString().replace("-","")+UUID.randomUUID().toString().replace("-","");
        String hash=hash(factor);
        try {
            if(!existed) jdbc.update("INSERT INTO iam_developer_eligibility(account_id,status,version,provisioned_by,reason,updated_at) VALUES(?,'ACTIVE',1,'isolated-test','professional fixture',?)",bytes(account),Timestamp.from(clock.instant()));
            jdbc.update("INSERT INTO iam_developer_factor(secret_hash,account_id,expires_at) VALUES(?,?,?)",hash,bytes(account),Timestamp.from(clock.instant().plusSeconds(300)));
            org.springframework.security.oauth2.jwt.Jwt jwt=application.getBean("jwtDecoder",JwtDecoder.class).decode(personal.accessToken());
            SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt,List.of()));
            Long version=jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?",Long.class,bytes(organization));
            ProfessionalReconciliationService.Result result=application.getBean(ProfessionalReconciliationService.class).reconcile(jwt,
                    new DeveloperCatalogService.Proof(account,password,factor),organization,
                    new ProfessionalReconciliationService.Command(account,null,password,"Professional administrator",version));
            return application.getBean(AuthenticationService.class).loginAccount(result.accountId(),new AccountLoginRequest(password));
        } finally {
            jdbc.update("DELETE FROM iam_developer_factor WHERE secret_hash=? AND account_id=?",hash,bytes(account));
            if(!existed) jdbc.update("DELETE FROM iam_developer_eligibility WHERE account_id=?",bytes(account));
            if(prior==null) SecurityContextHolder.clearContext();else SecurityContextHolder.getContext().setAuthentication(prior);
        }
    }
    static com.unidocs.auth.registration.api.RegistrationCompletionResponse selected(com.unidocs.auth.registration.api.RegistrationCompletionResponse original,UUID account) {
        return new com.unidocs.auth.registration.api.RegistrationCompletionResponse(original.id(),original.status(),original.userId(),account,original.accountGroupId(),original.completedAt());
    }
    private static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch(java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
