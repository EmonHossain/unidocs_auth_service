package com.unidocs.auth.registration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Clock;
import java.util.HexFormat;
import java.util.UUID;
import java.util.function.Function;
import com.unidocs.auth.authentication.api.AccountLoginRequest;
import com.unidocs.auth.authentication.api.LoginRequest;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.authorization.controlplane.DeveloperCatalogService;
import com.unidocs.auth.registration.api.RegistrationCompletionRequest;
import com.unidocs.auth.registration.api.RegistrationResponse;
import com.unidocs.auth.registration.api.RegistrationRequest;
import com.unidocs.auth.registration.api.VerificationRequest;
import com.unidocs.auth.registration.application.RegistrationService;
import com.unidocs.auth.registration.application.RegistrationProvisioningService;
import com.unidocs.auth.student.StudentPlatformService;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Isolated-test identities use the real protected reconciliation and appointment flows. */
final class StudentFixture {
    private StudentFixture() { }
    static com.unidocs.auth.registration.student.StudentRequests.View admit(ApplicationContext application,TokenResponse personal,UUID organization,String password) {
        JdbcTemplate jdbc=application.getBean(JdbcTemplate.class);
        String database=jdbc.queryForObject("SELECT DATABASE()",String.class);
        if(database==null||!database.toLowerCase(java.util.Locale.ROOT).contains("test")) throw new IllegalStateException("Student fixtures require an isolated test database");
        String domain="students-"+UUID.randomUUID()+".example.edu";
        jdbc.update("INSERT INTO institute_email_domain(organization_id,domain) VALUES(?,?)",bytes(organization),domain);
        com.unidocs.auth.registration.student.StudentAdmissionService service=application.getBean(com.unidocs.auth.registration.student.StudentAdmissionService.class);
        com.unidocs.auth.registration.student.StudentRequests.View pending=service.apply(personal.sessionId(),personal.loginAccountId(),organization,
                new com.unidocs.auth.registration.student.StudentRequests.Apply(personal.loginAccountId(),"student@"+domain,password),null);
        String code=application.getBean(RegistrationIntegrationTests.CapturingDelivery.class).tokens.get(pending.id());
        return service.verify(personal.sessionId(),personal.loginAccountId(),organization,pending.id(),
                new com.unidocs.auth.registration.student.StudentRequests.Verify(personal.loginAccountId(),code));
    }
    static TokenResponse administrator(ApplicationContext application,TokenResponse personal,String password,UUID organization) {
        TokenResponse applicant=personal(application,password);
        com.unidocs.auth.registration.student.StudentRequests.View student=admit(application,applicant,organization,password);
        developer(application,personal,password,proof->{
            Jwt jwt=(Jwt)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            return application.getBean(StudentPlatformService.class).appoint(jwt,proof,organization,new StudentPlatformService.Appointment(student.studentAccountId(),true,0));
        });
        return application.getBean(AuthenticationService.class).loginAccount(student.studentAccountId(),new AccountLoginRequest(password));
    }
    private static TokenResponse personal(ApplicationContext application,String password) {
        String email=UUID.randomUUID()+"@example.com";
        RegistrationService registrations=application.getBean(RegistrationService.class);
        RegistrationResponse pending=registrations.register(new RegistrationRequest("Student administrator test",email,password));
        RegistrationIntegrationTests.CapturingDelivery delivery=application.getBean(RegistrationIntegrationTests.CapturingDelivery.class);
        String code=delivery.tokens.get(pending.id());
        registrations.verify(pending.id(),new VerificationRequest(code));
        application.getBean(RegistrationProvisioningService.class).complete(pending.id(),new RegistrationCompletionRequest(code));
        return application.getBean(AuthenticationService.class).login(new LoginRequest(email,password));
    }
    static <T> T developer(ApplicationContext application,TokenResponse personal,String password,Function<DeveloperCatalogService.Proof,T> command) {
        JdbcTemplate jdbc=application.getBean(JdbcTemplate.class);String database=jdbc.queryForObject("SELECT DATABASE()",String.class);
        if(database==null||!database.toLowerCase(java.util.Locale.ROOT).contains("test")) throw new IllegalStateException("Student fixtures require an isolated test database");
        Clock clock=application.getBean(Clock.class);UUID account=personal.loginAccountId();Authentication prior=SecurityContextHolder.getContext().getAuthentication();
        boolean existed=Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM iam_developer_eligibility WHERE account_id=?)",Boolean.class,bytes(account)));
        String factor=UUID.randomUUID().toString().replace("-","")+UUID.randomUUID().toString().replace("-","");String hash=hash(factor);
        try {
            if(!existed) jdbc.update("INSERT INTO iam_developer_eligibility(account_id,status,version,provisioned_by,reason,updated_at) VALUES(?,'ACTIVE',1,'isolated-test','student fixture',?)",bytes(account),Timestamp.from(clock.instant()));
            jdbc.update("INSERT INTO iam_developer_factor(secret_hash,account_id,expires_at) VALUES(?,?,?)",hash,bytes(account),Timestamp.from(clock.instant().plusSeconds(300)));
            Jwt jwt=application.getBean("jwtDecoder",JwtDecoder.class).decode(personal.accessToken());SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt,java.util.List.of()));
            return command.apply(new DeveloperCatalogService.Proof(account,password,factor));
        } finally {
            jdbc.update("DELETE FROM iam_developer_factor WHERE secret_hash=? AND account_id=?",hash,bytes(account));
            if(!existed) jdbc.update("DELETE FROM iam_developer_eligibility WHERE account_id=?",bytes(account));
            if(prior==null) SecurityContextHolder.clearContext();else SecurityContextHolder.getContext().setAuthentication(prior);
        }
    }
    private static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch(java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
