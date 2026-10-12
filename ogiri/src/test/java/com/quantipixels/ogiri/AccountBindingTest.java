// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri;

import static org.junit.jupiter.api.Assertions.*;

import com.quantipixels.ogiri.account.*;
import com.quantipixels.ogiri.account.internal.DevisePasswordEncoder;
import com.quantipixels.ogiri.account.internal.JdbcDeviseAccountStore;
import com.quantipixels.ogiri.account.internal.OgiriSettings;
import com.quantipixels.ogiri.account.internal.RegistrationService;
import com.quantipixels.ogiri.account.internal.SignInService;
import com.quantipixels.ogiri.internal.*;
import com.quantipixels.ogiri.security.*;
import com.quantipixels.ogiri.security.internal.DtaAuthenticationToken;
import com.quantipixels.ogiri.security.internal.DtaCredential;
import com.quantipixels.ogiri.security.internal.OgiriTokenAuthenticationProvider;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.authentication.BadCredentialsException;

@Tag("database")
class AccountBindingTest {
    private JdbcTemplate jdbc;
    private AuthTransactions tx;
    private JdbcDeviseAccountStore accounts;
    private SessionRepository sessions;
    private SignInService signIn;
    private OgiriSettings settings;

    @BeforeEach
    void setup() {
        var source =
                new DriverManagerDataSource(
                        System.getenv("OGIRI_TEST_JDBC_URL"),
                        System.getenv("OGIRI_TEST_JDBC_USER"),
                        System.getenv("OGIRI_TEST_JDBC_PASSWORD"));
        jdbc = new JdbcTemplate(source);
        for (String table : List.of("ogiri_sessions", "ogiri_subject_locks", "users"))
            jdbc.execute("DROP TABLE IF EXISTS " + table);
        String engine = System.getenv("OGIRI_TEST_DATABASE");
        new ResourceDatabasePopulator(
                        new ClassPathResource("META-INF/ogiri/ogiri-" + engine + ".sql"),
                        new ClassPathResource("META-INF/ogiri/users-" + engine + ".sql"))
                .execute(source);
        tx = new AuthTransactions(source);
        accounts = new JdbcDeviseAccountStore(tx, "users", columns -> List.of());
        sessions = new SessionRepository(tx, SessionPolicy.defaults());
        settings = OgiriSettings.defaults();
        signIn =
                new SignInService(
                        accounts, tx, sessions, settings, new DevisePasswordEncoder(4), null);
    }

    private OgiriAccount create(String email) {
        return tx.write(
                () ->
                        accounts.create(
                                Map.of(
                                        "email",
                                        email,
                                        "uid",
                                        email,
                                        "encrypted_password",
                                        new DevisePasswordEncoder(4).encode("test-password"),
                                        "created_at",
                                        Instant.now(),
                                        "updated_at",
                                        Instant.now())));
    }

    private OgiriTokenAuthenticationProvider provider(boolean rotate) throws Exception {
        var components = OgiriSettings.class.getRecordComponents();
        Object[] values = new Object[components.length];
        Class<?>[] types = new Class<?>[components.length];
        for (int i = 0; i < components.length; i++) {
            types[i] = components[i].getType();
            values[i] = components[i].getAccessor().invoke(settings);
            if (components[i].getName().equals("changeHeadersOnEachRequest")) values[i] = rotate;
        }
        return new OgiriTokenAuthenticationProvider(
                accounts,
                tx,
                sessions,
                OgiriSettings.class.getDeclaredConstructor(types).newInstance(values));
    }

    @Test
    void alreadyAuthenticatedDeletionCannotDeleteAReplacementAccount() {
        var original = create("original@example.test");
        var issued = signIn.signIn(original.email(), "test-password").issued();
        jdbc.update("DELETE FROM users WHERE id = ?", Long.valueOf(original.id()));
        var replacement = create("replacement@example.test");
        jdbc.update(
                "UPDATE users SET id = ? WHERE id = ?",
                Long.valueOf(original.id()),
                Long.valueOf(replacement.id()));
        var registration =
                new RegistrationService(
                        accounts,
                        tx,
                        sessions,
                        settings,
                        new DevisePasswordEncoder(4),
                        signIn,
                        null,
                        null);
        assertThrows(DtaFailure.class, () -> registration.destroy(original, issued.session()));
        assertEquals(replacement.uid(), accounts.findById(original.id()).orElseThrow().uid());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void replacedAccountCannotInheritAnOldSession(boolean rotate) throws Exception {
        var original = create("original@example.test");
        var issued = signIn.signIn(original.email(), "test-password").issued();
        var provider = provider(rotate);
        authenticate(provider, original.uid(), issued);
        jdbc.update("DELETE FROM users WHERE id = ?", Long.valueOf(original.id()));
        var replacement = create("replacement@example.test");
        jdbc.update(
                "UPDATE users SET id = ? WHERE id = ?",
                Long.valueOf(original.id()),
                Long.valueOf(replacement.id()));
        assertThrows(
                BadCredentialsException.class,
                () -> authenticate(provider, replacement.uid(), issued));
        var fresh = signIn.signIn(replacement.email(), "test-password").issued();
        assertEquals(
                original.id(),
                authenticate(provider, replacement.uid(), fresh).getPrincipal().id());
    }

    @Test
    void upgradeBackfillsAccountGenerationsAndInvalidatesLegacySessions() throws Exception {
        var original = create("upgrade@example.test");
        var other = create("upgrade-other@example.test");
        signIn.signIn(original.email(), "test-password");
        jdbc.execute("ALTER TABLE users DROP COLUMN ogiri_generation");
        jdbc.execute("ALTER TABLE ogiri_sessions DROP COLUMN account_generation");
        var source = jdbc.getDataSource();
        new ResourceDatabasePopulator(
                        new org.springframework.core.io.FileSystemResource(
                                "../contracts/schema/migrations/001-account-generation-"
                                        + System.getenv("OGIRI_TEST_DATABASE")
                                        + ".sql"))
                .execute(source);
        var generation = accounts.findById(original.id()).orElseThrow().generation();
        assertFalse(generation.isBlank());
        var otherGeneration = accounts.findById(other.id()).orElseThrow().generation();
        assertFalse(otherGeneration.isBlank());
        assertNotEquals(generation, otherGeneration);
        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM ogiri_sessions", Integer.class));
        jdbc.update("DELETE FROM users WHERE id = ?", Long.valueOf(original.id()));
        var replacement = create("upgrade@example.test");
        assertNotEquals(generation, replacement.generation());
        assertNotEquals(otherGeneration, replacement.generation());
        assertFalse(replacement.view(false).containsKey("ogiri_generation"));
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
        "false,false",
        "false,true",
        "true,false",
        "true,true"
    })
    void sameUidAcrossProvidersResolvesThePresentedSession(boolean rotate, boolean oauthFirst)
            throws Exception {
        create("first@example.test");
        create("second@example.test");
        var first =
                tx.write(
                        () ->
                                accounts.update(
                                        "1",
                                        Map.of(
                                                "uid",
                                                "shared@example.test",
                                                "provider",
                                                oauthFirst ? "github" : "email")));
        var second =
                tx.write(
                        () ->
                                accounts.update(
                                        "2",
                                        Map.of(
                                                "uid",
                                                "shared@example.test",
                                                "provider",
                                                oauthFirst ? "email" : "github")));
        assertEquals(
                oauthFirst ? second.id() : first.id(),
                accounts.findByUid("shared@example.test", "email").orElseThrow().id());
        assertEquals(
                oauthFirst ? first.id() : second.id(),
                accounts.findByUid("shared@example.test", "github").orElseThrow().id());
        var provider = provider(rotate);
        for (var account : List.of(first, second)) {
            var issued =
                    tx.write(
                            () -> {
                                tx.lock(settings.subject(account));
                                accounts.lock(account.id());
                                return sessions.issueLocked(
                                        settings.subject(account),
                                        "same-client",
                                        account.generation());
                            });
            assertEquals(
                    account.id(),
                    authenticate(provider, account.uid(), issued).getPrincipal().id());
            assertThrows(
                    BadCredentialsException.class,
                    () -> authenticate(provider, "SHARED@example.test", issued));
        }
    }

    private OgiriAuthentication authenticate(
            OgiriTokenAuthenticationProvider provider, String uid, IssuedSession issued) {
        return (OgiriAuthentication)
                provider.authenticate(
                        new DtaAuthenticationToken(
                                new DtaCredential(
                                        uid, issued.session().client(), issued.token(), false)));
    }
}
