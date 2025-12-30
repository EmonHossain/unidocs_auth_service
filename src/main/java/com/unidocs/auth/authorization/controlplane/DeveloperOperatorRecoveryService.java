package com.unidocs.auth.authorization.controlplane;

import java.net.URI;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.security.bruteforce.LoginAttackProtection;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Purpose-bound operator password recovery and audited factor replacement. */
@Service
@ConditionalOnProperty(name="auth.developer.operator.enabled",havingValue="true")
public class DeveloperOperatorRecoveryService {
    public record RecoveryRequest(String username,String email) { }
    public record RecoveryCompletion(String username,String email,String token,String recoveryCode,
            String newPassword,String confirmation) {
        @Override public String toString() { return "RecoveryCompletion[REDACTED]"; }
    }
    public record CredentialChange(String currentPassword,String factor,String newPassword,String confirmation) {
        @Override public String toString() { return "CredentialChange[REDACTED]"; }
    }
    public record NewProofs(List<String> oneUseFactors,List<String> recoveryCodes) {
        @Override public String toString() { return "NewProofs[REDACTED]"; }
    }
    private record Operator(UUID id,String passwordHash,long version,String email) { }
    private record RecoveryProof(String hash,long version,Instant expiresAt,int attempts,String delivery,Instant consumedAt) { }
    private static final SecureRandom RANDOM=new SecureRandom();
    private final JdbcTemplate jdbc;
    private final PasswordEncoder passwords;
    private final DeveloperOperatorGate gate;
    private final LoginAttackProtection protection;
    private final ObjectProvider<JavaMailSender> mail;
    private final TransactionTemplate transactions;
    private final Clock clock;
    private final String mailFrom;
    private final String publicOrigin;

    /** Wires separate operator proofs without product-account dependencies.
     * @param jdbc operator persistence
     * @param passwords adaptive password verifier
     * @param gate current operator session and one-use proof gate
     * @param protection distributed request throttle
     * @param mail recovery delivery
     * @param manager transaction manager
     * @param clock time source
     * @param mailFrom configured sender
     * @param publicOrigin allowlisted recovery portal origin
     */
    public DeveloperOperatorRecoveryService(JdbcTemplate jdbc,PasswordEncoder passwords,DeveloperOperatorGate gate,
            LoginAttackProtection protection,ObjectProvider<JavaMailSender> mail,PlatformTransactionManager manager,
            Clock clock,@Value("${auth.mail.from:no-reply@unidocs.local}") String mailFrom,
            @Value("${auth.developer.recovery.origin:}") String publicOrigin) {
        this.jdbc=jdbc;this.passwords=passwords;this.gate=gate;this.protection=protection;this.mail=mail;
        this.transactions=new TransactionTemplate(manager);this.clock=clock;this.mailFrom=mailFrom;
        this.publicOrigin=validatedOrigin(publicOrigin);
    }

    /** Sends a generic response while issuing a short-lived email proof only for a verified operator.
     * @param request canonical username and established recovery email
     * @param peer request peer for distributed throttling
     */
    public void request(RecoveryRequest request,String peer) {
        if(request==null || !validUsername(request.username()) || !validEmail(request.email()))return;
        String username=request.username().strip().toLowerCase(Locale.ROOT);
        String email=request.email().strip().toLowerCase(Locale.ROOT);
        try {
            protection.protect(peer,"operator-recovery:"+username,()->{
                JavaMailSender sender=mail.getIfAvailable();
                if(sender==null || publicOrigin.isEmpty())return Boolean.TRUE;
                String token=secret();String hash=DeveloperGate.hash(token);Instant now=clock.instant();
                Operator target=transactions.execute(status->{
                    List<Operator> rows=jdbc.query("SELECT id,password_hash,credential_version,email FROM iam_developer_operator WHERE username=? AND email=? AND email_verified=TRUE AND status='ACTIVE' FOR UPDATE",
                            (row,index)->new Operator(uuid(row.getBytes(1)),row.getString(2),row.getLong(3),row.getString(4)),username,email);
                    if(rows.size()!=1)return null;Operator operator=rows.getFirst();
                    jdbc.update("""
                            INSERT INTO iam_developer_recovery_proof(operator_id,token_hash,credential_version,expires_at,delivery_state,created_at)
                            VALUES(?,?,?,?, 'PENDING',?) ON DUPLICATE KEY UPDATE token_hash=VALUES(token_hash),
                            credential_version=VALUES(credential_version),expires_at=VALUES(expires_at),
                            failed_attempts=0,delivery_state='PENDING',created_at=VALUES(created_at),consumed_at=NULL
                            """,bytes(operator.id()),hash,operator.version(),Timestamp.from(now.plus(Duration.ofMinutes(15))),Timestamp.from(now));
                    audit(operator.id(),null,"DEVELOPER_RECOVERY_REQUESTED",now);
                    return operator;
                });
                if(target==null)return Boolean.TRUE;
                try {
                    SimpleMailMessage message=new SimpleMailMessage();message.setFrom(mailFrom);message.setTo(target.email());
                    message.setSubject("UniDocs developer password recovery");
                    message.setText("Open "+publicOrigin+"/developer/reset#token="+token+" to reset your developer password. "
                            +"Use an offline recovery code as the second proof. This link expires in 15 minutes.");
                    sender.send(message);
                    delivery(hash,"SENT");
                } catch(RuntimeException unavailable) { delivery(hash,"FAILED"); }
                return Boolean.TRUE;
            });
        } catch(RuntimeException unavailable) { /* Keep the acknowledgement identical during denial or delivery outages. */ }
    }

    /** Changes the password using the live session, current password, and one-use factor.
     * @param jwt verified operator token
     * @param request current and replacement credentials
     * @return replacement factors and recovery codes shown once
     */
    public NewProofs change(Jwt jwt,CredentialChange request) {
        if(request==null || !validPassword(request.newPassword()) || !request.newPassword().equals(request.confirmation())
                || request.newPassword().equals(request.currentPassword()))throw new AuthenticationFailure();
        String replacement=passwords.encode(request.newPassword());NewProofs proofs=newProofs();
        return gate.executeCredentialChange(jwt,request.currentPassword(),request.factor(),context->{
            Operator current=operator(context.operatorId(),true);
            if(current==null || passwords.matches(request.newPassword(),current.passwordHash()))throw new AuthenticationFailure();
            replace(current,replacement,context.now(),proofs,"DEVELOPER_PASSWORD_CHANGED",context.sessionId());
            return proofs;
        });
    }

    /** Completes recovery with both email and independent offline code, then revokes every operator session.
     * @param request recovery proofs and replacement password
     * @return replacement factors and recovery codes shown once
     */
    public NewProofs complete(RecoveryCompletion request) {
        if(request==null || !validUsername(request.username()) || !validEmail(request.email())
                || !hexSecret(request.token()) || !hexSecret(request.recoveryCode())
                || !validPassword(request.newPassword()) || !request.newPassword().equals(request.confirmation()))
            throw new AuthenticationFailure();
        String replacement=passwords.encode(request.newPassword());NewProofs proofs=newProofs();
        Boolean accepted=transactions.execute(status->{
            String username=request.username().strip().toLowerCase(Locale.ROOT);
            String email=request.email().strip().toLowerCase(Locale.ROOT);
            List<Operator> operators=jdbc.query("SELECT id,password_hash,credential_version,email FROM iam_developer_operator WHERE username=? AND email=? AND email_verified=TRUE AND status='ACTIVE' FOR UPDATE",
                    (row,index)->new Operator(uuid(row.getBytes(1)),row.getString(2),row.getLong(3),row.getString(4)),username,email);
            if(operators.size()!=1)return false;Operator current=operators.getFirst();Instant now=clock.instant();
            List<RecoveryProof> rows=jdbc.query("SELECT token_hash,credential_version,expires_at,failed_attempts,delivery_state,consumed_at FROM iam_developer_recovery_proof WHERE operator_id=? FOR UPDATE",
                    (row,index)->new RecoveryProof(row.getString(1),row.getLong(2),row.getTimestamp(3).toInstant(),row.getInt(4),
                            row.getString(5),row.getTimestamp(6)==null?null:row.getTimestamp(6).toInstant()),bytes(current.id()));
            if(rows.size()!=1)return false;RecoveryProof proof=rows.getFirst();
            if(proof.attempts()>=5 || proof.consumedAt()!=null || !proof.expiresAt().isAfter(now)
                    || !"SENT".equals(proof.delivery()) || proof.version()!=current.version())return false;
            Integer codes=jdbc.queryForObject("SELECT COUNT(*) FROM iam_developer_recovery_code WHERE operator_id=? AND secret_hash=? AND consumed_at IS NULL",
                    Integer.class,bytes(current.id()),DeveloperGate.hash(request.recoveryCode()));
            if(!same(proof.hash(),DeveloperGate.hash(request.token())) || codes==null || codes!=1
                    || passwords.matches(request.newPassword(),current.passwordHash())) {
                jdbc.update("UPDATE iam_developer_recovery_proof SET failed_attempts=failed_attempts+1 WHERE operator_id=?",bytes(current.id()));
                return false;
            }
            replace(current,replacement,now,proofs,"DEVELOPER_PASSWORD_RECOVERED",null);
            return true;
        });
        if(!Boolean.TRUE.equals(accepted))throw new AuthenticationFailure();
        return proofs;
    }

    /** Rotates offline recovery codes after a current password and factor proof.
     * @param jwt verified operator token
     * @param password current password
     * @param factor independent one-use factor
     * @return replacement recovery codes shown once
     */
    public List<String> rotateRecoveryCodes(Jwt jwt,String password,String factor) {
        List<String> codes=secrets(10);
        return gate.execute(jwt,password,factor,null,context->{
            jdbc.update("DELETE FROM iam_developer_recovery_code WHERE operator_id=?",bytes(context.operatorId()));
            for(String code:codes)jdbc.update("INSERT INTO iam_developer_recovery_code(secret_hash,operator_id,created_at) VALUES(?,?,?)",
                    DeveloperGate.hash(code),bytes(context.operatorId()),Timestamp.from(context.now()));
            audit(context.operatorId(),context.sessionId(),"DEVELOPER_RECOVERY_CODES_ROTATED",context.now());
            notice(context.operatorId(),"DEVELOPER_RECOVERY_CODES_ROTATED",context.now());
            return List.copyOf(codes);
        });
    }

    /** Replenishes one-use operation factors and retires the entire prior set.
     * @param jwt verified operator token
     * @param password current password
     * @param factor an unused factor from the current set
     * @return replacement factors shown once
     */
    public List<String> rotateFactors(Jwt jwt,String password,String factor) {
        List<String> factors=secrets(20);
        return gate.executeCredentialChange(jwt,password,factor,context->{
            jdbc.update("DELETE FROM iam_developer_operator_factor WHERE operator_id=?",bytes(context.operatorId()));
            for(String replacement:factors)jdbc.update("INSERT INTO iam_developer_operator_factor(secret_hash,operator_id,expires_at) VALUES(?,?,?)",
                    DeveloperGate.hash(replacement),bytes(context.operatorId()),Timestamp.from(context.now().plus(Duration.ofDays(30))));
            audit(context.operatorId(),context.sessionId(),"DEVELOPER_FACTORS_ROTATED",context.now());
            notice(context.operatorId(),"DEVELOPER_FACTORS_ROTATED",context.now());
            return List.copyOf(factors);
        });
    }

    private void replace(Operator current,String hash,Instant now,NewProofs proofs,String action,UUID session) {
        jdbc.update("UPDATE iam_developer_operator SET password_hash=?,credential_version=credential_version+1,failed_attempts=0,lock_window_at=NULL,updated_at=? WHERE id=?",
                hash,Timestamp.from(now),bytes(current.id()));
        jdbc.update("UPDATE iam_developer_session SET status='REVOKED',revoked_at=? WHERE operator_id=? AND status='ACTIVE'",
                Timestamp.from(now),bytes(current.id()));
        jdbc.update("DELETE FROM iam_developer_operator_factor WHERE operator_id=?",bytes(current.id()));
        jdbc.update("DELETE FROM iam_developer_recovery_code WHERE operator_id=?",bytes(current.id()));
        jdbc.update("DELETE FROM iam_developer_setup_proof WHERE operator_id=?",bytes(current.id()));
        jdbc.update("DELETE FROM iam_developer_recovery_proof WHERE operator_id=?",bytes(current.id()));
        for(String factor:proofs.oneUseFactors())jdbc.update("INSERT INTO iam_developer_operator_factor(secret_hash,operator_id,expires_at) VALUES(?,?,?)",
                DeveloperGate.hash(factor),bytes(current.id()),Timestamp.from(now.plus(Duration.ofDays(30))));
        for(String code:proofs.recoveryCodes())jdbc.update("INSERT INTO iam_developer_recovery_code(secret_hash,operator_id,created_at) VALUES(?,?,?)",
                DeveloperGate.hash(code),bytes(current.id()),Timestamp.from(now));
        audit(current.id(),session,action,now);
        notice(current.id(),action,now);
    }
    private Operator operator(UUID id,boolean lock) {
        return jdbc.query("SELECT id,password_hash,credential_version,email FROM iam_developer_operator WHERE id=? AND status='ACTIVE' AND email_verified=TRUE"+(lock?" FOR UPDATE":""),
                (row,index)->new Operator(uuid(row.getBytes(1)),row.getString(2),row.getLong(3),row.getString(4)),bytes(id)).stream().findFirst().orElse(null);
    }
    private void delivery(String hash,String state) {
        transactions.executeWithoutResult(status->jdbc.update("UPDATE iam_developer_recovery_proof SET delivery_state=? WHERE token_hash=? AND delivery_state='PENDING'",state,hash));
    }
    private void audit(UUID operator,UUID session,String action,Instant now) {
        jdbc.update("INSERT INTO iam_developer_operator_audit(id,operator_id,session_id,action_key,occurred_at) VALUES(?,?,?,?,?)",
                bytes(UUID.randomUUID()),bytes(operator),session==null?null:bytes(session),action,Timestamp.from(now));
    }
    private void notice(UUID operator,String action,Instant now) {
        jdbc.update("INSERT INTO iam_developer_security_notice(id,operator_id,action_key,available_at,created_at) VALUES(?,?,?,?,?)",
                bytes(UUID.randomUUID()),bytes(operator),action,Timestamp.from(now),Timestamp.from(now));
    }
    private static NewProofs newProofs() { return new NewProofs(List.copyOf(secrets(20)),List.copyOf(secrets(10))); }
    private static List<String> secrets(int count) { List<String> result=new ArrayList<>();for(int index=0;index<count;index++)result.add(secret());return result; }
    private static String secret() { byte[] value=new byte[32];RANDOM.nextBytes(value);return HexFormat.of().formatHex(value); }
    private static UUID uuid(byte[] value) { ByteBuffer buffer=ByteBuffer.wrap(value);return new UUID(buffer.getLong(),buffer.getLong()); }
    private static boolean same(String left,String right) { return left!=null && right!=null && MessageDigest.isEqual(left.getBytes(java.nio.charset.StandardCharsets.US_ASCII),right.getBytes(java.nio.charset.StandardCharsets.US_ASCII)); }
    private static boolean validUsername(String value) { return value!=null && value.strip().matches("[A-Za-z][A-Za-z0-9._-]{2,127}"); }
    private static boolean validEmail(String value) { return value!=null && value.length()<=254 && value.matches("[^@\\s]+@[^@\\s]+\\.[^@\\s]+"); }
    private static boolean hexSecret(String value) { return value!=null && value.matches("[a-f0-9]{64}"); }
    private static boolean validPassword(String value) { return value!=null && value.length()>=15 && value.length()<=128 && !value.toLowerCase(Locale.ROOT).matches(".*(password|unidocadmin|123456|qwerty|admin).*"); }
    private static String validatedOrigin(String candidate) {
        if(candidate==null || candidate.isBlank())return "";
        URI uri=URI.create(candidate);
        if(uri.getHost()==null || uri.getUserInfo()!=null || uri.getQuery()!=null || uri.getFragment()!=null
                || !uri.getPath().isEmpty() || !("https".equals(uri.getScheme())
                || "http".equals(uri.getScheme()) && ("localhost".equals(uri.getHost()) || "127.0.0.1".equals(uri.getHost()))))
            throw new IllegalArgumentException("Invalid developer recovery origin.");
        return candidate;
    }
}
