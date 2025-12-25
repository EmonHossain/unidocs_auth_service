package com.unidocs.auth.authorization.controlplane;

import java.time.Duration;
import java.sql.Timestamp;
import java.util.UUID;
import java.util.function.Function;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.credential.application.PasswordAndPinVerifier;
import com.unidocs.auth.account.domain.AccountChallenge.Method;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.persistence.SessionRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Eligibility is deliberately independent from the editable application role catalog. */
@Component
public class DeveloperGate {
    private final SessionAccess access;
    private final SessionRepository sessions;
    private final JdbcTemplate jdbc;
    private final PasswordAndPinVerifier passwords;
    private final java.time.Clock clock;
    public DeveloperGate(SessionAccess access, SessionRepository sessions, JdbcTemplate jdbc, PasswordAndPinVerifier passwords,java.time.Clock clock) {
        this.access=access; this.sessions=sessions; this.jdbc=jdbc; this.passwords=passwords;this.clock=clock;
    }
    private record Result<T>(T value, boolean proofFailed) { }
    public <T> T execute(Jwt jwt, UUID account, String password, String secondFactor, String requestKey, Function<SessionAccess.Context,T> command) {
        return executeForGroups(jwt,account,password,secondFactor,requestKey,java.util.List.of(),command);
    }
    public <T> T executeForGroups(Jwt jwt, UUID account, String password, String secondFactor, String requestKey,
            java.util.List<UUID> otherGroups,Function<SessionAccess.Context,T> command) {
        if(jwt==null || account==null) throw new AuthenticationFailure();
        checkToken(jwt);
        UUID sid=UUID.fromString(jwt.getClaimAsString("sid")),subject=UUID.fromString(jwt.getSubject());
        UUID actorGroup=sessions.sessionGroup(sid).orElseThrow(AuthenticationFailure::new);
        SessionRepository.Owner actor=sessions.owner(actorGroup).orElseThrow(AuthenticationFailure::new);
        java.util.List<java.util.Map<String,Object>> admission=jdbc.queryForList("SELECT status,failed_attempts,proof_window_at FROM iam_developer_eligibility WHERE account_id=?",bytes(account));
        if(admission.size()!=1 || !"ACTIVE".equals(admission.getFirst().get("status")))throw denied();
        Timestamp admittedWindow=(Timestamp)admission.getFirst().get("proof_window_at");
        if(((Number)admission.getFirst().get("failed_attempts")).intValue()>=5 && admittedWindow!=null
                && admittedWindow.toInstant().plus(Duration.ofMinutes(15)).isAfter(clock.instant()))
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,"PROOF_ATTEMPTS_EXCEEDED");
        // The expensive password derivation runs outside the fenced SQL transaction. The locked
        // identity below must still match every credential dependency before this proof is used.
        SessionRepository.Identity candidate=sessions.accountIdentity(account).orElseThrow(DeveloperGate::denied);
        if(!candidate.userId().equals(actor.userId()))throw denied();
        boolean passwordVerified=candidate.available() && passwords.verify(Method.PASSWORD,password,candidate.passwordHash());
        Function<SessionAccess.Context,Result<T>> work=context -> {
            if(jwt.getExpiresAt()==null || !jwt.getExpiresAt().isAfter(context.now())) throw new AuthenticationFailure();
            if(context.session().authenticatedAt().plus(Duration.ofMinutes(15)).isBefore(context.now()))
                throw new ResponseStatusException(HttpStatus.FORBIDDEN,"FRESH_AUTHENTICATION_REQUIRED");
            sessions.liveGrant(context.session(),account,context.now()).orElseThrow(DeveloperGate::denied);
            java.util.List<java.util.Map<String,Object>> rows=jdbc.queryForList(
                "SELECT status,version,failed_attempts,proof_window_at FROM iam_developer_eligibility WHERE account_id=? FOR UPDATE",bytes(account));
            if(rows.size()!=1 || !"ACTIVE".equals(rows.getFirst().get("status"))) throw denied();
            java.util.Map<String,Object> row=rows.getFirst();
            long eligibilityVersion=((Number)row.getOrDefault("version",1L)).longValue();
            Timestamp window=(Timestamp)row.get("proof_window_at");
            int attempts=((Number)row.get("failed_attempts")).intValue();
            boolean expired=window==null || !window.toInstant().plus(Duration.ofMinutes(15)).isAfter(context.now());
            if(expired) attempts=0;
            if(attempts>=5) throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,"PROOF_ATTEMPTS_EXCEEDED");
            SessionRepository.Identity identity=sessions.accountIdentity(account).orElseThrow(DeveloperGate::denied);
            if(!identity.available() || !identity.userId().equals(context.owner().userId())) throw denied();
            boolean validPassword=passwordVerified && candidate.id().equals(identity.id())
                && candidate.credentialVersion()==identity.credentialVersion()
                && candidate.passwordHash().equals(identity.passwordHash());
            String factorHash=secondFactor!=null && secondFactor.matches("[a-f0-9]{64}")?hash(secondFactor):"";
            java.util.List<java.util.Map<String,Object>> factors=jdbc.queryForList(
                "SELECT consumed_key,consumed_at FROM iam_developer_factor WHERE secret_hash=? AND account_id=? AND expires_at>? FOR UPDATE",
                factorHash,bytes(account),Timestamp.from(clock.instant()));
            boolean validFactor=factors.size()==1 && (factors.getFirst().get("consumed_at")==null
                || requestKey!=null && requestKey.equals(factors.getFirst().get("consumed_key")));
            if(!validPassword || !validFactor) {
                jdbc.update("UPDATE iam_developer_eligibility SET failed_attempts=?,proof_window_at=? WHERE account_id=?",
                    attempts+1,expired?Timestamp.from(context.now()):window,bytes(account));
                audit(context,account,"DEVELOPER_PROOF_FAILED",account,eligibilityVersion);
                return new Result<T>(null,true);
            }
            jdbc.update("UPDATE iam_developer_factor SET consumed_key=?,consumed_at=? WHERE secret_hash=? AND consumed_at IS NULL",
                requestKey,Timestamp.from(context.now()),factorHash);
            jdbc.update("UPDATE iam_developer_eligibility SET failed_attempts=0,proof_window_at=? WHERE account_id=?",Timestamp.from(context.now()),bytes(account));
            SessionAccess.Context fresh=checkCurrent(jwt,context,account);
            checkFactor(account,secondFactor);
            T value=command.apply(fresh);
            fresh=checkCurrent(jwt,fresh,account);
            checkFactor(account,secondFactor);
            audit(fresh,account,"DEVELOPER_PROOF_SUCCEEDED",account,eligibilityVersion);
            sessions.touch(fresh.session(),sessions.liveGrant(fresh.session(),account,fresh.now()).orElseThrow(DeveloperGate::denied),fresh.now());
            return new Result<T>(value,false);
        };
        Result<T> result=otherGroups.isEmpty()?access.execute(sid,subject,work):access.executeForGroups(sid,subject,otherGroups,work);
        if(result.proofFailed()) throw denied();
        return result.value();
    }
    void checkToken(Jwt jwt){if(jwt.getExpiresAt()==null || !jwt.getExpiresAt().isAfter(clock.instant()))throw new AuthenticationFailure();}
    void checkFactor(UUID account,String code){
        Integer current=jdbc.queryForObject("SELECT COUNT(*) FROM iam_developer_factor WHERE account_id=? AND secret_hash=? AND expires_at>?",Integer.class,
            bytes(account),hash(code),Timestamp.from(clock.instant()));
        if(current==null || current!=1)throw denied();
    }
    SessionAccess.Context checkCurrent(Jwt jwt,SessionAccess.Context context,UUID account){
        java.time.Instant now=clock.instant();checkToken(jwt);
        if(!context.session().activeAt(now))throw new AuthenticationFailure();
        if(context.session().authenticatedAt().plus(Duration.ofMinutes(15)).isBefore(now))throw denied();
        com.unidocs.auth.session.domain.SessionAccountGrant grant=sessions.liveGrant(context.session(),account,now).orElseThrow(DeveloperGate::denied);
        return new SessionAccess.Context(context.session(),context.owner(),grant,now);
    }
    static String hash(String value) {
        try { return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8))); }
        catch(java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    void audit(SessionAccess.Context context,UUID account,String action,UUID aggregate,long version) {
        jdbc.update("INSERT INTO iam_controlplane_audit(id,account_id,session_id,action_key,aggregate_id,aggregate_version,occurred_at) VALUES(?,?,?,?,?,?,?)",
            bytes(UUID.randomUUID()),bytes(account),bytes(context.session().id()),action,bytes(aggregate),version,Timestamp.from(context.now()));
    }
    private static ResponseStatusException denied() {return new ResponseStatusException(HttpStatus.FORBIDDEN,"DEVELOPER_ACCESS_DENIED");}
}
