package com.unidocs.auth.authorization.controlplane;

import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Enforces fresh operator sessions, current credentials and one-use proof per ACL request. */
@Component
@ConditionalOnProperty(name="auth.developer.operator.enabled",havingValue="true")
public class DeveloperOperatorGate {
    public record Context(UUID operatorId,UUID sessionId,Instant now) { }
    private record Candidate(UUID id,String passwordHash,long version) { }
    private record OperatorProof(String passwordHash,long version,int attempts,Instant lockWindow) { }
    private record FactorUse(String consumedKey,Instant consumedAt) { }
    private record LiveSession(Instant authenticatedAt,Instant expiresAt,long version,long operatorVersion,
            String operatorStatus,boolean emailVerified) { }
    private record Outcome<T>(T value,boolean failedProof) { }
    private final JdbcTemplate jdbc;
    private final PasswordEncoder passwords;
    private final Clock clock;
    private final TransactionTemplate transactions;

    /** Uses short SQL transactions for proof consumption and catalog changes.
     * @param jdbc operator persistence
     * @param passwords current-password verifier
     * @param clock time source
     * @param manager transaction manager
     */
    public DeveloperOperatorGate(JdbcTemplate jdbc,PasswordEncoder passwords,Clock clock,PlatformTransactionManager manager) {
        this.jdbc=jdbc;this.passwords=passwords;this.clock=clock;this.transactions=new TransactionTemplate(manager);
    }

    /** Runs one protected catalog operation inside a fenced operator transaction.
     * @param jwt verified operator token
     * @param password current operator password
     * @param factor independent one-use proof
     * @param requestKey idempotency key for a mutation, or null for a read
     * @param action protected catalog operation
     * @return the protected operation result
     * @throws ResponseStatusException when proof or current admission fails
     */
    public <T> T execute(Jwt jwt,String password,String factor,String requestKey,Function<Context,T> action) {
        return execute(jwt,password,factor,requestKey,action,false);
    }

    /** Runs a terminal credential change that invalidates its own session before commit.
     * @param jwt verified operator token
     * @param password current operator password
     * @param factor independent one-use proof
     * @param action credential change and revocation in the same transaction
     * @return the credential action result
     */
    public <T> T executeCredentialChange(Jwt jwt,String password,String factor,Function<Context,T> action) {
        return execute(jwt,password,factor,null,action,true);
    }

    private <T> T execute(Jwt jwt,String password,String factor,String requestKey,Function<Context,T> action,
            boolean terminal) {
        if(jwt==null || password==null || password.isBlank() || password.length()>128
                || factor==null || !factor.matches("[a-f0-9]{64}"))throw denied();
        UUID operator=UUID.fromString(jwt.getSubject());UUID session=UUID.fromString(jwt.getClaimAsString("sid"));
        Candidate candidate=candidate(operator);
        boolean passwordMatched=candidate!=null && passwords.matches(password,candidate.passwordHash());
        Outcome<T> outcome=transactions.execute(status->{
            Context context=validate(jwt,operator,session,true);
            List<OperatorProof> rows=jdbc.query("SELECT password_hash,credential_version,failed_attempts,lock_window_at FROM iam_developer_operator WHERE id=? FOR UPDATE",
                    (row,index)->new OperatorProof(row.getString(1),row.getLong(2),row.getInt(3),
                            row.getTimestamp(4)==null?null:row.getTimestamp(4).toInstant()),bytes(operator));
            if(rows.size()!=1)throw denied();OperatorProof row=rows.getFirst();
            int attempts=row.attempts();Instant window=row.lockWindow();
            if(attempts>=5 && window!=null && window.plus(Duration.ofMinutes(15)).isAfter(context.now()))
                throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,"OPERATOR_PROOF_LOCKED");
            if(window==null || !window.plus(Duration.ofMinutes(15)).isAfter(context.now())) {
                attempts=0;
                window=context.now();
            }
            String factorHash=DeveloperGate.hash(factor);
            List<FactorUse> proofs=jdbc.query("SELECT consumed_key,consumed_at FROM iam_developer_operator_factor WHERE operator_id=? AND secret_hash=? AND expires_at>? FOR UPDATE",
                    (proof,index)->new FactorUse(proof.getString(1),proof.getTimestamp(2)==null?null:proof.getTimestamp(2).toInstant()),
                    bytes(operator),factorHash,Timestamp.from(context.now()));
            boolean factorMatched=proofs.size()==1 && (proofs.getFirst().consumedAt()==null
                    || requestKey!=null && requestKey.equals(proofs.getFirst().consumedKey()));
            if(!passwordMatched || candidate==null || candidate.version()!=row.version()
                    || !candidate.passwordHash().equals(row.passwordHash()) || !factorMatched) {
                jdbc.update("UPDATE iam_developer_operator SET failed_attempts=?,lock_window_at=? WHERE id=?",
                        attempts+1,Timestamp.from(window),bytes(operator));
                audit(context,"DEVELOPER_PROOF_FAILED",null,null);
                return new Outcome<T>(null,true);
            }
            jdbc.update("UPDATE iam_developer_operator_factor SET consumed_key=?,consumed_at=? WHERE operator_id=? AND secret_hash=? AND consumed_at IS NULL",
                    requestKey,Timestamp.from(context.now()),bytes(operator),factorHash);
            jdbc.update("UPDATE iam_developer_operator SET failed_attempts=0,lock_window_at=NULL WHERE id=?",bytes(operator));
            recheck(jwt,context,factorHash,requestKey);
            T value=action.apply(context);
            if(!terminal)recheck(jwt,context,factorHash,requestKey);
            audit(context,"DEVELOPER_PROOF_SUCCEEDED",null,null);
            return new Outcome<>(value,false);
        });
        if(outcome==null || outcome.failedProof())throw denied();return outcome.value();
    }

    /** Rechecks current operator status and the consumed proof before commit.
     * @param jwt verified operator token
     * @param context original admitted operator context
     * @param factorHash verifier for the consumed factor
     * @param requestKey mutation idempotency key, or null for a read
     * @throws ResponseStatusException when current proof is no longer valid
     */
    public void recheck(Jwt jwt,Context context,String factorHash,String requestKey) {
        validate(jwt,context.operatorId(),context.sessionId(),true);
        Integer count=jdbc.queryForObject("SELECT COUNT(*) FROM iam_developer_operator_factor WHERE operator_id=? AND secret_hash=? AND expires_at>? AND consumed_at IS NOT NULL AND consumed_key<=>?",
                Integer.class,bytes(context.operatorId()),factorHash,Timestamp.from(clock.instant()),requestKey);
        if(count==null || count!=1)throw denied();
    }

    /** Writes operator attribution separately from legacy product-account audit.
     * @param context admitted operator context
     * @param action audited action
     * @param aggregate affected aggregate, if any
     * @param version affected version, if any
     */
    public void audit(Context context,String action,UUID aggregate,Long version) {
        audit(context,action,aggregate,version,null);
    }
    /** Writes an operator audit with the reviewed business reason for a mutation.
     * @param context admitted operator context
     * @param action audited action
     * @param aggregate affected aggregate, if any
     * @param version affected version, if any
     * @param reason reviewed business reason
     */
    public void audit(Context context,String action,UUID aggregate,Long version,String reason) {
        jdbc.update("INSERT INTO iam_developer_operator_audit(id,operator_id,session_id,action_key,aggregate_id,aggregate_version,reason,occurred_at) VALUES(?,?,?,?,?,?,?,?)",
                bytes(UUID.randomUUID()),bytes(context.operatorId()),bytes(context.sessionId()),action,
                aggregate==null?null:bytes(aggregate),version,reason,Timestamp.from(clock.instant()));
    }

    private Context validate(Jwt jwt,UUID operator,UUID session,boolean fresh) {
        Instant now=clock.instant();
        if(jwt.getExpiresAt()==null || !jwt.getExpiresAt().isAfter(now)
                || !"DEVELOPER_OPERATOR".equals(jwt.getClaimAsString("realm")))throw new AuthenticationFailure();
        List<LiveSession> sessions=jdbc.query("""
                SELECT s.authenticated_at,s.expires_at,s.credential_version,o.credential_version operator_version,
                    o.status,o.email_verified FROM iam_developer_session s JOIN iam_developer_operator o ON o.id=s.operator_id
                WHERE s.id=? AND s.operator_id=? AND s.status='ACTIVE' FOR UPDATE
                """,(row,index)->new LiveSession(row.getTimestamp(1).toInstant(),row.getTimestamp(2).toInstant(),
                        row.getLong(3),row.getLong(4),row.getString(5),row.getBoolean(6)),bytes(session),bytes(operator));
        if(sessions.size()!=1)throw new AuthenticationFailure();LiveSession row=sessions.getFirst();
        if(!row.expiresAt().isAfter(now) || !"ACTIVE".equals(row.operatorStatus())
                || !row.emailVerified() || row.version()!=row.operatorVersion()
                || fresh && row.authenticatedAt().plus(Duration.ofMinutes(15)).isBefore(now))throw new AuthenticationFailure();
        return new Context(operator,session,now);
    }
    private Candidate candidate(UUID operator) {
        return jdbc.query("SELECT id,password_hash,credential_version FROM iam_developer_operator WHERE id=? AND status='ACTIVE'",
                (row,index)->new Candidate(uuid(row.getBytes(1)),row.getString(2),row.getLong(3)),bytes(operator)).stream().findFirst().orElse(null);
    }
    private static UUID uuid(byte[] value) { ByteBuffer buffer=ByteBuffer.wrap(value);return new UUID(buffer.getLong(),buffer.getLong()); }
    private static ResponseStatusException denied() { return new ResponseStatusException(HttpStatus.FORBIDDEN,"DEVELOPER_ACCESS_DENIED"); }
}
