package com.unidocs.auth.authorization.controlplane;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Timestamp;
import java.time.Clock;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Seeds only the stable, unusable-until-enrolled operator identity. */
@Configuration(proxyBeanMethods = false)
public class DeveloperOperatorBootstrap {
    @Bean
    @ConditionalOnProperty(name = "auth.developer.bootstrap.enabled", havingValue = "true")
    ApplicationRunner bootstrapDeveloperOperator(JdbcTemplate jdbc, PasswordEncoder passwords, Clock clock,
            @Value("${auth.developer.activation-secret-file:/run/secrets/application/developer-activation}") String activationFile) {
        return arguments -> {
            String activationHash = activationHash(Path.of(activationFile));
            Timestamp now = Timestamp.from(clock.instant());
            jdbc.update("""
                    INSERT INTO iam_developer_operator(id,bootstrap_key,username,password_hash,status,
                        credential_version,activation_hash,created_at,updated_at)
                    VALUES(?,'BUILTIN_CREATOR','unidocadmin',?,'SETUP',1,?,?,?)
                    ON DUPLICATE KEY UPDATE id=id
                    """, bytes(UUID.randomUUID()), passwords.encode("admin"), activationHash, now, now);
            Integer builtIn=jdbc.queryForObject("SELECT COUNT(*) FROM iam_developer_operator WHERE bootstrap_key='BUILTIN_CREATOR'",Integer.class);
            if(builtIn==null || builtIn!=1)throw new IllegalStateException("Built-in developer operator provisioning failed.");
            // A later provisioning run may supply the installation secret, but never restore a consumed one.
            if (activationHash != null) jdbc.update("""
                    UPDATE iam_developer_operator SET activation_hash=?,updated_at=?
                    WHERE bootstrap_key='BUILTIN_CREATOR' AND status='SETUP' AND activation_hash IS NULL
                    """, activationHash, now);
        };
    }

    static String activationHash(Path path) throws IOException {
        if (!Files.isRegularFile(path)) return null;
        String proof = Files.readString(path, StandardCharsets.UTF_8).strip();
        if (!proof.matches("[a-f0-9]{64}")) throw new IllegalStateException("Invalid developer activation secret file.");
        return DeveloperGate.hash(proof);
    }
}
