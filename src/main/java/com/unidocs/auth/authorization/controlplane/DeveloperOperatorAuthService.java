package com.unidocs.auth.authorization.controlplane;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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
import com.unidocs.auth.security.jwt.DeveloperOperatorTokens;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Separate credential, session, and setup lifecycle for developer operators. */
@Service
@ConditionalOnProperty(name="auth.developer.operator.enabled",havingValue="true")
public class DeveloperOperatorAuthService {
    public record SetupStart(String activation,String bootstrapPassword,String username,String newPassword,String email) {
        @Override public String toString() { return "SetupStart[REDACTED]"; }
    }
    public record SetupComplete(String activation,String emailCode) {
        @Override public String toString() { return "SetupComplete[REDACTED]"; }
    }
    public record Login(String username,String password) {
        @Override public String toString() { return "Login[REDACTED]"; }
    }
    public record Refresh(UUID sessionId,String refreshSecret) {
        @Override public String toString() { return "Refresh[REDACTED]"; }
    }
    public record Session(String accessToken,String refreshSecret,UUID sessionId) {
        @Override public String toString() { return "Session[REDACTED]"; }
    }
    public record Enrollment(List<String> oneUseFactors,List<String> recoveryCodes) {
        @Override public String toString() { return "Enrollment[REDACTED]"; }
    }
    private record Operator(UUID id,String username,String passwordHash,String status,long version,
            String activationHash,boolean emailVerified,int attempts,Instant lockWindow) { }
    private record SetupProof(String username,String passwordHash,String email,String codeHash,
            Instant expiresAt,String deliveryState,int failedAttempts) { }
    private record RefreshState(UUID operatorId,long sessionVersion,String sessionStatus,Instant expiresAt,
            String refreshHash,Instant refreshExpiresAt,String operatorStatus,long operatorVersion) { }
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Duration SESSION_LIFETIME = Duration.ofMinutes(15);
    private final JdbcTemplate jdbc;
    private final PasswordEncoder passwords;
    private final DeveloperOperatorTokens tokens;
    private final Clock clock;
    private final TransactionTemplate transactions;
    private final ObjectProvider<JavaMailSender> mail;
    private final LoginAttackProtection protection;
    private final String mailFrom;
    private final String dummyHash;

    /** Wires the dedicated operator credential store and distributed abuse protection.
     * @param jdbc operator persistence
     * @param passwords password verifier
     * @param tokens operator token issuer
     * @param clock time source
     * @param manager transaction manager
     * @param mail setup email sender
     * @param protection login abuse protection
     * @param mailFrom sender address
     */
    public DeveloperOperatorAuthService(JdbcTemplate jdbc,PasswordEncoder passwords,DeveloperOperatorTokens tokens,
            Clock clock,PlatformTransactionManager manager,ObjectProvider<JavaMailSender> mail,
            LoginAttackProtection protection,@org.springframework.beans.factory.annotation.Value("${auth.mail.from:no-reply@unidocs.local}") String mailFrom) {
        this.jdbc=jdbc;this.passwords=passwords;this.tokens=tokens;this.clock=clock;this.mail=mail;
        this.protection=protection;this.mailFrom=mailFrom;this.dummyHash=passwords.encode(UUID.randomUUID().toString());
        this.transactions=new TransactionTemplate(manager);
    }

    /** Starts installer-bound email verification without enabling ACL access.
     * @param request first-use credential and installation proof
     * @param peer request peer for abuse protection
     * @throws AuthenticationFailure when setup proof is invalid or unavailable
     */
    public void startSetup(SetupStart request,String peer) {
        if(request==null || !validSecret(request.activation()) || !validSecret(request.bootstrapPassword())
                || !validUsername(request.username()) || !validEmail(request.email()) || !validPassword(request.newPassword()))
            throw new AuthenticationFailure();
        String normalized=request.username().strip().toLowerCase(Locale.ROOT);
        String email=request.email().strip().toLowerCase(Locale.ROOT);
        String passwordHash=passwords.encode(request.newPassword());
        String code=secret();
        protection.protect(peer,"operator-setup:BUILTIN_CREATOR",()->{
            Boolean accepted=transactions.execute(status->{
                Operator operator=operatorByBootstrap(true);
                if(operator==null || !"SETUP".equals(operator.status()) || operator.activationHash()==null
                        || !same(operator.activationHash(),DeveloperGate.hash(request.activation()))
                        || !passwords.matches(request.bootstrapPassword(),operator.passwordHash())) return false;
                Instant now=clock.instant();
                jdbc.update("""
                    INSERT INTO iam_developer_setup_proof(operator_id,pending_username,pending_password_hash,pending_email,
                        code_hash,expires_at,delivery_state,created_at)
                    VALUES(?,?,?,?,?,?,'PENDING',?) ON DUPLICATE KEY UPDATE pending_username=VALUES(pending_username),
                        pending_password_hash=VALUES(pending_password_hash),pending_email=VALUES(pending_email),
                        code_hash=VALUES(code_hash),expires_at=VALUES(expires_at),failed_attempts=0,
                        delivery_state='PENDING',created_at=VALUES(created_at)
                    """,bytes(operator.id()),normalized,passwordHash,email,DeveloperGate.hash(code),
                        Timestamp.from(now.plus(Duration.ofMinutes(10))),Timestamp.from(now));
                audit(operator.id(),null,"DEVELOPER_SETUP_STARTED",null,null,now);
                return true;
            });
            if(!Boolean.TRUE.equals(accepted)) throw new AuthenticationFailure();
            JavaMailSender sender=mail.getIfAvailable();
            if(sender==null) { markDelivery(code,"FAILED"); throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"SETUP_MAIL_UNAVAILABLE"); }
            try {
                SimpleMailMessage message=new SimpleMailMessage();message.setFrom(mailFrom);message.setTo(email);
                message.setSubject("Verify your UniDocs developer setup");
                message.setText("Your developer setup code is "+code+". It expires in 10 minutes. Do not share it.");
                sender.send(message);markDelivery(code,"SENT");
            } catch(RuntimeException failure) { markDelivery(code,"FAILED");throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"SETUP_MAIL_UNAVAILABLE"); }
            return Boolean.TRUE;
        });
    }

    /** Completes setup atomically and returns single-use factors once for offline storage.
     * @param request installation and email proofs
     * @return the one-time enrollment factor set
     * @throws AuthenticationFailure when setup proof is invalid or expired
     */
    public Enrollment completeSetup(SetupComplete request) {
        if(request==null || !validSecret(request.activation()) || !validSecret(request.emailCode())) throw new AuthenticationFailure();
        List<String> factors=new ArrayList<>();for(int index=0;index<20;index++)factors.add(secret());
        List<String> recoveryCodes=new ArrayList<>();for(int index=0;index<10;index++)recoveryCodes.add(secret());
        Enrollment enrollment=transactions.execute(status->{
            Operator operator=operatorByBootstrap(true);
            if(operator==null || !"SETUP".equals(operator.status()) || operator.activationHash()==null
                    || !same(operator.activationHash(),DeveloperGate.hash(request.activation()))) throw new AuthenticationFailure();
            List<SetupProof> rows=jdbc.query("SELECT pending_username,pending_password_hash,pending_email,code_hash,expires_at,delivery_state,failed_attempts FROM iam_developer_setup_proof WHERE operator_id=? FOR UPDATE",
                    (row,index)->new SetupProof(row.getString(1),row.getString(2),row.getString(3),row.getString(4),
                            row.getTimestamp(5).toInstant(),row.getString(6),row.getInt(7)),bytes(operator.id()));
            if(rows.size()!=1)throw new AuthenticationFailure();
            SetupProof proof=rows.getFirst();Instant now=clock.instant();
            if(proof.failedAttempts()>=5 || !"SENT".equals(proof.deliveryState())
                    || !proof.expiresAt().isAfter(now))throw new AuthenticationFailure();
            if(!same(proof.codeHash(),DeveloperGate.hash(request.emailCode()))) {
                jdbc.update("UPDATE iam_developer_setup_proof SET failed_attempts=failed_attempts+1 WHERE operator_id=?",bytes(operator.id()));
                return null;
            }
            String username=proof.username();
            String email=proof.email();
            String passwordHash=proof.passwordHash();
            jdbc.update("UPDATE iam_developer_operator SET username=?,password_hash=?,email=?,email_verified=TRUE,status='ACTIVE',credential_version=credential_version+1,activation_hash=NULL,updated_at=? WHERE id=?",
                    username,passwordHash,email,Timestamp.from(now),bytes(operator.id()));
            jdbc.update("DELETE FROM iam_developer_setup_proof WHERE operator_id=?",bytes(operator.id()));
            for(String factor:factors) jdbc.update("INSERT INTO iam_developer_operator_factor(secret_hash,operator_id,expires_at) VALUES(?,?,?)",
                    DeveloperGate.hash(factor),bytes(operator.id()),Timestamp.from(now.plus(Duration.ofDays(30))));
            for(String code:recoveryCodes) jdbc.update("INSERT INTO iam_developer_recovery_code(secret_hash,operator_id,created_at) VALUES(?,?,?)",
                    DeveloperGate.hash(code),bytes(operator.id()),Timestamp.from(now));
            audit(operator.id(),null,"DEVELOPER_SETUP_COMPLETED",null,operator.version()+1,now);
            return new Enrollment(List.copyOf(factors),List.copyOf(recoveryCodes));
        });
        if(enrollment==null)throw new AuthenticationFailure();
        return enrollment;
    }

    /** Authenticates only an active, verified developer operator.
     * @param request operator credentials
     * @param peer request peer for abuse protection
     * @return a separate operator session
     * @throws AuthenticationFailure when credentials or operator state fail admission
     */
    public Session login(Login request,String peer) {
        if(request==null || !validUsername(request.username()) || !validSecret(request.password()))throw new AuthenticationFailure();
        String username=request.username().strip().toLowerCase(Locale.ROOT);
        return protection.protect(peer,"operator-login:"+username,()->{
            Operator candidate=operatorByUsername(username,false);
            boolean matched=passwords.matches(request.password(),candidate==null?dummyHash:candidate.passwordHash());
            Session session=transactions.execute(status->{
                Operator current=operatorByUsername(username,true);Instant now=clock.instant();
                if(current==null || !"ACTIVE".equals(current.status()) || !current.emailVerified())return null;
                boolean activeWindow=current.lockWindow()!=null
                        && current.lockWindow().plus(Duration.ofMinutes(15)).isAfter(now);
                if(current.attempts()>=5 && activeWindow)return null;
                if(!matched || candidate==null || !candidate.id().equals(current.id())
                        || candidate.version()!=current.version() || !candidate.passwordHash().equals(current.passwordHash())) {
                    jdbc.update("UPDATE iam_developer_operator SET failed_attempts=?,lock_window_at=? WHERE id=?",
                            Math.min(5,(activeWindow?current.attempts():0)+1),
                            Timestamp.from(activeWindow?current.lockWindow():now),bytes(current.id()));
                    audit(current.id(),null,"DEVELOPER_LOGIN_FAILED",null,null,now);return null;
                }
                UUID sid=UUID.randomUUID();String refresh=secret();
                jdbc.update("INSERT INTO iam_developer_session(id,operator_id,credential_version,status,authenticated_at,expires_at,refresh_hash,refresh_expires_at,created_at) VALUES(?,?,?,'ACTIVE',?,?,?,?,?)",
                        bytes(sid),bytes(current.id()),current.version(),Timestamp.from(now),Timestamp.from(now.plus(SESSION_LIFETIME)),
                        DeveloperGate.hash(refresh),Timestamp.from(now.plus(SESSION_LIFETIME)),Timestamp.from(now));
                jdbc.update("UPDATE iam_developer_operator SET failed_attempts=0,lock_window_at=NULL WHERE id=?",bytes(current.id()));
                audit(current.id(),sid,"DEVELOPER_LOGIN_SUCCEEDED",null,null,now);
                return new Session(tokens.issue(current.id(),sid),refresh,sid);
            });
            if(session==null)throw new AuthenticationFailure();return session;
        });
    }

    /** Rotates a separate operator refresh secret and rejects replay.
     * @param request current session and refresh proof
     * @return the rotated session tokens
     * @throws AuthenticationFailure when the proof is invalid, expired, or replayed
     */
    public Session refresh(Refresh request) {
        if(request==null || request.sessionId()==null || !validSecret(request.refreshSecret()))throw new AuthenticationFailure();
        String replacement=secret();
        Session result=transactions.execute(status->{
            List<RefreshState> rows=jdbc.query("SELECT s.operator_id,s.credential_version,s.status,s.expires_at,s.refresh_hash,s.refresh_expires_at,o.status,o.credential_version FROM iam_developer_session s JOIN iam_developer_operator o ON o.id=s.operator_id WHERE s.id=? FOR UPDATE",
                    (row,index)->new RefreshState(uuid(row.getBytes(1)),row.getLong(2),row.getString(3),
                            row.getTimestamp(4).toInstant(),row.getString(5),row.getTimestamp(6).toInstant(),
                            row.getString(7),row.getLong(8)),bytes(request.sessionId()));
            if(rows.size()!=1)return null;RefreshState row=rows.getFirst();Instant now=clock.instant();UUID operator=row.operatorId();
            if(!"ACTIVE".equals(row.sessionStatus()) || !"ACTIVE".equals(row.operatorStatus())
                    || !row.expiresAt().isAfter(now) || !row.refreshExpiresAt().isAfter(now)
                    || row.sessionVersion()!=row.operatorVersion())return null;
            if(!same(row.refreshHash(),DeveloperGate.hash(request.refreshSecret()))) {
                jdbc.update("UPDATE iam_developer_session SET status='REVOKED',revoked_at=? WHERE id=?",Timestamp.from(now),bytes(request.sessionId()));
                audit(operator,request.sessionId(),"DEVELOPER_REFRESH_REPLAY",null,null,now);return null;
            }
            jdbc.update("UPDATE iam_developer_session SET refresh_hash=?,rotation=rotation+1 WHERE id=?",DeveloperGate.hash(replacement),bytes(request.sessionId()));
            return new Session(tokens.issue(operator,request.sessionId()),replacement,request.sessionId());
        });
        if(result==null)throw new AuthenticationFailure();return result;
    }

    /** Revokes the current operator session without affecting product sessions.
     * @param operator authenticated operator ID
     * @param session authenticated session ID
     */
    public void logout(UUID operator,UUID session) {
        transactions.executeWithoutResult(status->{
            Instant now=clock.instant();
            jdbc.update("UPDATE iam_developer_session SET status='REVOKED',revoked_at=? WHERE id=? AND operator_id=? AND status='ACTIVE'",
                    Timestamp.from(now),bytes(session),bytes(operator));
            audit(operator,session,"DEVELOPER_LOGOUT",null,null,now);
        });
    }

    private void markDelivery(String code,String state) {
        transactions.executeWithoutResult(status->jdbc.update("UPDATE iam_developer_setup_proof SET delivery_state=? WHERE operator_id=(SELECT id FROM iam_developer_operator WHERE bootstrap_key='BUILTIN_CREATOR') AND code_hash=?",state,DeveloperGate.hash(code)));
    }
    private Operator operatorByBootstrap(boolean lock) {
        return jdbc.query("SELECT id,username,password_hash,status,credential_version,activation_hash,email_verified,failed_attempts,lock_window_at FROM iam_developer_operator WHERE bootstrap_key='BUILTIN_CREATOR'"+(lock?" FOR UPDATE":""),
                (row,index)->new Operator(uuid(row.getBytes(1)),row.getString(2),row.getString(3),row.getString(4),row.getLong(5),row.getString(6),row.getBoolean(7),row.getInt(8),row.getTimestamp(9)==null?null:row.getTimestamp(9).toInstant())).stream().findFirst().orElse(null);
    }
    private Operator operatorByUsername(String username,boolean lock) {
        return jdbc.query("SELECT id,username,password_hash,status,credential_version,activation_hash,email_verified,failed_attempts,lock_window_at FROM iam_developer_operator WHERE username=?"+(lock?" FOR UPDATE":""),
                (row,index)->new Operator(uuid(row.getBytes(1)),row.getString(2),row.getString(3),row.getString(4),row.getLong(5),row.getString(6),row.getBoolean(7),row.getInt(8),row.getTimestamp(9)==null?null:row.getTimestamp(9).toInstant()),username).stream().findFirst().orElse(null);
    }
    private void audit(UUID operator,UUID session,String action,UUID aggregate,Long version,Instant now) {
        jdbc.update("INSERT INTO iam_developer_operator_audit(id,operator_id,session_id,action_key,aggregate_id,aggregate_version,occurred_at) VALUES(?,?,?,?,?,?,?)",
                bytes(UUID.randomUUID()),bytes(operator),session==null?null:bytes(session),action,aggregate==null?null:bytes(aggregate),version,Timestamp.from(now));
    }
    private static String secret() { byte[] bytes=new byte[32];RANDOM.nextBytes(bytes);return HexFormat.of().formatHex(bytes); }
    private static boolean same(String left,String right) { return left!=null && right!=null && MessageDigest.isEqual(left.getBytes(StandardCharsets.US_ASCII),right.getBytes(StandardCharsets.US_ASCII)); }
    private static boolean validSecret(String value) { return value!=null && !value.isBlank() && value.length()<=128; }
    private static boolean validUsername(String value) { return value!=null && value.strip().matches("[A-Za-z][A-Za-z0-9._-]{2,127}"); }
    private static boolean validEmail(String value) { return value!=null && value.length()<=254 && value.matches("[^@\\s]+@[^@\\s]+\\.[^@\\s]+"); }
    private static boolean validPassword(String value) { return value!=null && value.length()>=15 && value.length()<=128 && !value.toLowerCase(Locale.ROOT).matches(".*(password|unidocadmin|123456|qwerty|admin).*?"); }
    private static UUID uuid(byte[] value) { ByteBuffer buffer=ByteBuffer.wrap(value);return new UUID(buffer.getLong(),buffer.getLong()); }
}
