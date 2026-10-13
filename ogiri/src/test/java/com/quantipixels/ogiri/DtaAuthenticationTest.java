// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.quantipixels.ogiri.account.internal.DevisePasswordEncoder;
import com.quantipixels.ogiri.account.internal.JdbcDeviseAccountStore;
import com.quantipixels.ogiri.account.internal.OgiriSettings;
import com.quantipixels.ogiri.account.internal.SignInService;
import com.quantipixels.ogiri.internal.AuthTransactions;
import com.quantipixels.ogiri.internal.SessionRepository;
import com.quantipixels.ogiri.security.OgiriRuntime;
import com.quantipixels.ogiri.security.internal.DtaAuthenticationToken;
import com.quantipixels.ogiri.security.internal.DtaCredential;
import com.quantipixels.ogiri.security.internal.OgiriAuthenticationFilter;
import com.quantipixels.ogiri.security.internal.OgiriTokenAuthenticationProvider;
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
        var sessions = new SessionRepository(tx, SessionPolicy.defaults());
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
        var signIn = new SignInService(accounts, tx, sessions, settings, passwords, null);
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
            var response = new MockHttpServletResponse();
            filter.doFilter(
                    request,
                    response,
                    (req, res) -> {
                        throw new AssertionError("Mixed identities must not enter the controller");
                    });
            assertEquals(401, response.getStatus());
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    void sameRealmInstancesAndChainsNeverShareRequestStateOrFilterMarkers() throws Exception {
        var otherAccounts =
                new JdbcDeviseAccountStore(runtime.transactions(), "admins", columns -> List.of());
        var otherSignIn =
                new SignInService(
                        otherAccounts,
                        runtime.transactions(),
                        runtime.sessions(),
                        runtime.settings(),
                        new DevisePasswordEncoder(),
                        null);
        var other =
                new OgiriRuntime(
                        runtime.settings(),
                        runtime.transactions(),
                        runtime.sessions(),
                        otherAccounts,
                        otherSignIn);
        var firstRealms = new com.quantipixels.ogiri.security.OgiriRealms(runtime, List.of());
        var secondRealms = new com.quantipixels.ogiri.security.OgiriRealms(other, List.of());
        var first =
                new com.quantipixels.ogiri.security.internal.OgiriSecurityContextRepository(
                        firstRealms);
        var second =
                new com.quantipixels.ogiri.security.internal.OgiriSecurityContextRepository(
                        secondRealms);
        var anotherChain =
                new com.quantipixels.ogiri.security.internal.OgiriSecurityContextRepository(
                        firstRealms);
        var request = new MockHttpServletRequest("GET", "/me");
        request.setServletPath("/me");
        request.addHeader("uid", login.account().uid());
        request.addHeader("client", login.issued().session().client());
        request.addHeader("access-token", login.issued().token());
        var response = new MockHttpServletResponse();
        var filter =
                new com.quantipixels.ogiri.security.internal.OgiriRealmAuthenticationFilter(
                        firstRealms, first);
        var nested =
                new com.quantipixels.ogiri.security.internal.OgiriRealmAuthenticationFilter(
                        secondRealms, second);
        SecurityContextHolder.clearContext();
        try {
            filter.doFilter(
                    request,
                    response,
                    (req, res) -> {
                        org.junit.jupiter.api.Assertions.assertTrue(first.containsContext(request));
                        org.junit.jupiter.api.Assertions.assertFalse(
                                second.containsContext(request));
                        org.junit.jupiter.api.Assertions.assertFalse(
                                anotherChain.containsContext(request));
                        org.junit.jupiter.api.Assertions.assertNotNull(
                                request.getAttribute(runtime.responseCredentialsAttribute()));
                        org.junit.jupiter.api.Assertions.assertNull(
                                request.getAttribute(other.responseCredentialsAttribute()));
                        nested.doFilter(
                                req,
                                res,
                                (r, s) -> {
                                    throw new AssertionError(
                                            "The second instance must reject the earlier authenticated identity");
                                });
                        for (String header : List.of("uid", "client", "access-token"))
                            request.removeHeader(header);
                        nested.doFilter(
                                req,
                                res,
                                (r, s) ->
                                        org.junit.jupiter.api.Assertions.assertNull(
                                                SecurityContextHolder.getContext()
                                                        .getAuthentication(),
                                                "A different instance without credentials must not inherit the first principal"));
                    });
            assertEquals(401, response.getStatus());
        } finally {
            SecurityContextHolder.clearContext();
        }
    }
}
