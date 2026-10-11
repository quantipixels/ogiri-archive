// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.quantipixels.ogiri.account.DevisePasswordEncoder;
import com.quantipixels.ogiri.account.JdbcDeviseAccountStore;
import com.quantipixels.ogiri.account.OgiriSettings;
import com.quantipixels.ogiri.account.SignInService;
import com.quantipixels.ogiri.security.DtaAuthenticationToken;
import com.quantipixels.ogiri.security.DtaCredential;
import com.quantipixels.ogiri.security.OgiriAuthenticationFilter;
import com.quantipixels.ogiri.security.OgiriRuntime;
import com.quantipixels.ogiri.security.OgiriTokenAuthenticationProvider;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

@Tag("database")
class DtaAuthenticationTest {
    static OgiriRuntime runtime;
    static SignInService.Result login;

    @BeforeAll
    static void setup() {
        var source =
                new DriverManagerDataSource(
                        System.getenv("OGIRI_TEST_JDBC_URL"),
                        System.getenv("OGIRI_TEST_JDBC_USER"),
                        System.getenv("OGIRI_TEST_JDBC_PASSWORD"));
        var tx = new AuthTransactions(source);
        var jdbc = tx.jdbc();
        for (String table : List.of("ogiri_sessions", "ogiri_subject_locks", "users")) {
            jdbc.execute("DROP TABLE IF EXISTS " + table);
        }
        String engine = System.getenv("OGIRI_TEST_DATABASE");
        new ResourceDatabasePopulator(
                        new ClassPathResource("META-INF/ogiri/ogiri-" + engine + ".sql"),
                        new ClassPathResource("META-INF/ogiri/users-" + engine + ".sql"))
                .execute(source);
        var settings = OgiriSettings.defaults();
        var sessions = new JdbcSessions(tx, SessionPolicy.defaults());
        var accounts =
                new JdbcDeviseAccountStore(
                        tx,
                        "users",
                        attributes -> List.of(new SimpleGrantedAuthority("ROLE_USER")));
        var passwords = new DevisePasswordEncoder();
        tx.write(
                () ->
                        accounts.create(
                                Map.of(
                                        "provider",
                                        "email",
                                        "uid",
                                        "owner@example.com",
                                        "email",
                                        "owner@example.com",
                                        "encrypted_password",
                                        passwords.encode("test-password"),
                                        "created_at",
                                        Instant.ofEpochMilli(tx.now()),
                                        "updated_at",
                                        Instant.ofEpochMilli(tx.now()))));
        var signIn = new SignInService(accounts, tx, sessions, settings, passwords);
        runtime = new OgiriRuntime(settings, tx, sessions, accounts, signIn);
        login = signIn.signIn(" OWNER@example.com ", "test-password");
    }

    @Test
    void allThreeFieldsBindAndSubjectIsPrimaryKey() {
        var provider =
                new OgiriTokenAuthenticationProvider(
                        runtime.accounts(),
                        runtime.transactions(),
                        runtime.sessions(),
                        runtime.settings());
        var session = login.issued().session();
        assertEquals(login.account().id(), session.subject().subjectId());
        assertThrows(
                BadCredentialsException.class,
                () ->
                        provider.authenticate(
                                new DtaAuthenticationToken(
                                        new DtaCredential(
                                                "unknown@example.com",
                                                session.client(),
                                                login.issued().token(),
                                                false))));
        assertThrows(
                BadCredentialsException.class,
                () ->
                        provider.authenticate(
                                new DtaAuthenticationToken(
                                        new DtaCredential(
                                                login.account().uid(),
                                                "wrong-client",
                                                login.issued().token(),
                                                false))));
    }

    @Test
    void earlierSameOrDifferentIdentityCannotDonateAuthorities() throws Exception {
        var provider =
                new OgiriTokenAuthenticationProvider(
                        runtime.accounts(),
                        runtime.transactions(),
                        runtime.sessions(),
                        runtime.settings());
        var filter = new OgiriAuthenticationFilter(runtime, new ProviderManager(provider));
        for (String identity : List.of(login.account().uid(), "another-identity")) {
            SecurityContextHolder.getContext()
                    .setAuthentication(
                            UsernamePasswordAuthenticationToken.authenticated(
                                    identity,
                                    "",
                                    List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));
            var request = new MockHttpServletRequest("GET", "/me");
            request.setServletPath("/me");
            request.addHeader("uid", login.account().uid());
            request.addHeader("client", login.issued().session().client());
            request.addHeader("access-token", login.issued().token());
            filter.doFilter(
                    request,
                    new MockHttpServletResponse(),
                    (req, response) -> {
                        var resolved = SecurityContextHolder.getContext().getAuthentication();
                        assertEquals(
                                login.account().id(),
                                ((com.quantipixels.ogiri.account.OgiriAccount)
                                                resolved.getPrincipal())
                                        .id());
                        assertTrue(
                                resolved.getAuthorities()
                                        .contains(new SimpleGrantedAuthority("ROLE_USER")));
                        assertFalse(
                                resolved.getAuthorities()
                                        .contains(new SimpleGrantedAuthority("ROLE_ADMIN")));
                    });
            SecurityContextHolder.clearContext();
        }
    }
}
