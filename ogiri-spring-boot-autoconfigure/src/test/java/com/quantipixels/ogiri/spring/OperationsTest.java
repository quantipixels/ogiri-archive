// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.quantipixels.ogiri.SessionStoreException;
import com.quantipixels.ogiri.account.AccountStore;
import com.quantipixels.ogiri.account.internal.SignInService;
import com.quantipixels.ogiri.internal.AuthTransactions;
import com.quantipixels.ogiri.internal.DtaFailure;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ApplicationListener;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;

@Tag("database")
@ExtendWith(OutputCaptureExtension.class)
class OperationsTest {
    private final List<AbstractAuthenticationEvent> events = new ArrayList<>();

    private WebApplicationContextRunner runner() {
        var source =
                new DriverManagerDataSource(
                        System.getenv("OGIRI_TEST_JDBC_URL"),
                        System.getenv("OGIRI_TEST_JDBC_USER"),
                        System.getenv("OGIRI_TEST_JDBC_PASSWORD"));
        var jdbc = new org.springframework.jdbc.core.JdbcTemplate(source);
        for (String table : List.of("ogiri_sessions", "ogiri_subject_locks", "users"))
            jdbc.execute("DROP TABLE IF EXISTS " + table);
        String engine = System.getenv("OGIRI_TEST_DATABASE");
        new ResourceDatabasePopulator(
                        new ClassPathResource("META-INF/ogiri/ogiri-" + engine + ".sql"),
                        new ClassPathResource("META-INF/ogiri/users-" + engine + ".sql"))
                .execute(source);
        return new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(OgiriAutoConfiguration.class))
                .withBean(DataSource.class, () -> source)
                .withBean(
                        org.springframework.mail.javamail.JavaMailSender.class,
                        org.springframework.mail.javamail.JavaMailSenderImpl::new)
                .withInitializer(
                        context ->
                                context.addApplicationListener(
                                        (ApplicationListener<AbstractAuthenticationEvent>)
                                                events::add))
                .withPropertyValues(
                        "ogiri.public-base-url=https://example.test", "ogiri.bcrypt-cost=4");
    }

    @Test
    void signInEventsAndLogsContainNoCredentials(CapturedOutput output) {
        runner().withPropertyValues(
                        "ogiri.lockable=true",
                        "ogiri.maximum-attempts=1",
                        "ogiri.unlock-strategy=time")
                .run(
                        context -> {
                            assertThat(context).hasNotFailed();
                            var tx = context.getBean(AuthTransactions.class);
                            var accounts = context.getBean(AccountStore.class);
                            var encoder =
                                    context.getBean(
                                                    com.quantipixels.ogiri.account.internal
                                                            .OgiriPasswords.class)
                                            .encoder();
                            var account =
                                    tx.write(
                                            () ->
                                                    accounts.create(
                                                            Map.of(
                                                                    "provider",
                                                                    "email",
                                                                    "uid",
                                                                    "secret@example.test",
                                                                    "email",
                                                                    "secret@example.test",
                                                                    "encrypted_password",
                                                                    encoder.encode(
                                                                            "private-password"),
                                                                    "created_at",
                                                                    Instant.now(),
                                                                    "updated_at",
                                                                    Instant.now())));
                            var signIn = context.getBean(SignInService.class);
                            var login = signIn.signIn("secret@example.test", "private-password");
                            assertThatThrownBy(
                                            () ->
                                                    signIn.signIn(
                                                            "secret@example.test", "wrong-secret"))
                                    .isInstanceOf(DtaFailure.class);
                            assertThatThrownBy(
                                            () ->
                                                    signIn.signIn(
                                                            "secret@example.test",
                                                            "private-password"))
                                    .isInstanceOf(DtaFailure.class);
                            tx.write(
                                    () ->
                                            context.getBean(
                                                            com.quantipixels.ogiri.account.internal
                                                                    .ActivationService.class)
                                                    .clearLockLocked(
                                                            accounts.lock(account.id())
                                                                    .orElseThrow()));
                            assertThat(events)
                                    .extracting(Object::getClass)
                                    .containsExactly(
                                            AuthenticationSuccessEvent.class,
                                            AuthenticationFailureBadCredentialsEvent.class,
                                            AuthenticationFailureLockedEvent.class);
                            assertThat(events)
                                    .allSatisfy(
                                            event -> {
                                                assertThat(
                                                                event.getAuthentication()
                                                                        .getCredentials())
                                                        .isNull();
                                                assertThat(event.getAuthentication().getName())
                                                        .isEqualTo("users:secret@example.test");
                                                assertSafe(
                                                        event,
                                                        "private-password",
                                                        "wrong-secret",
                                                        account.getPassword(),
                                                        login.issued().token(),
                                                        login.issued().session().client());
                                            });
                            assertThat(output)
                                    .contains(
                                            "Ogiri sign-in failed",
                                            "Ogiri account locked",
                                            "Ogiri account unlocked")
                                    .doesNotContain(
                                            "secret@example.test",
                                            "private-password",
                                            "wrong-secret");
                        });
    }

    @Test
    void unconfirmedSignInPublishesDisabled() {
        runner().withPropertyValues("ogiri.confirmable=true")
                .run(
                        context -> {
                            var tx = context.getBean(AuthTransactions.class);
                            var encoder =
                                    context.getBean(
                                                    com.quantipixels.ogiri.account.internal
                                                            .OgiriPasswords.class)
                                            .encoder();
                            tx.write(
                                    () ->
                                            context.getBean(AccountStore.class)
                                                    .create(
                                                            Map.of(
                                                                    "provider",
                                                                    "email",
                                                                    "uid",
                                                                    "inactive@example.test",
                                                                    "email",
                                                                    "inactive@example.test",
                                                                    "encrypted_password",
                                                                    encoder.encode("secret"),
                                                                    "created_at",
                                                                    Instant.now(),
                                                                    "updated_at",
                                                                    Instant.now())));
                            assertThatThrownBy(
                                            () ->
                                                    context.getBean(SignInService.class)
                                                            .signIn(
                                                                    "inactive@example.test",
                                                                    "secret"))
                                    .isInstanceOf(DtaFailure.class);
                            assertThat(events)
                                    .singleElement()
                                    .isInstanceOf(AuthenticationFailureDisabledEvent.class)
                                    .satisfies(
                                            event -> {
                                                assertThat(event.getAuthentication().getPrincipal())
                                                        .isEqualTo("users:inactive@example.test");
                                                assertSafe(event, "secret");
                                            });
                        });
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"users", "admins"})
    void tokenManagerPublishesRedactedSuccessAndFailure(String realm) {
        runner().withPropertyValues("ogiri.realm=" + realm)
                .run(
                        context -> {
                            var runtime =
                                    context.getBean(
                                            com.quantipixels.ogiri.security.OgiriRuntime.class);
                            var encoder =
                                    context.getBean(
                                                    com.quantipixels.ogiri.account.internal
                                                            .OgiriPasswords.class)
                                            .encoder();
                            runtime.transactions()
                                    .write(
                                            () ->
                                                    runtime.accounts()
                                                            .create(
                                                                    Map.of(
                                                                            "provider",
                                                                            "email",
                                                                            "uid",
                                                                            "token@example.test",
                                                                            "email",
                                                                            "token@example.test",
                                                                            "encrypted_password",
                                                                            encoder.encode(
                                                                                    "private-password"),
                                                                            "created_at",
                                                                            Instant.now(),
                                                                            "updated_at",
                                                                            Instant.now())));
                            var login =
                                    runtime.signIn()
                                            .signIn("token@example.test", "private-password");
                            assertThat(events)
                                    .singleElement()
                                    .satisfies(
                                            event -> {
                                                assertThat(event.getAuthentication().getPrincipal())
                                                        .isEqualTo(realm + ":token@example.test");
                                                assertSafe(
                                                        event,
                                                        "private-password",
                                                        login.account().getPassword(),
                                                        login.issued().token(),
                                                        login.issued().session().client());
                                            });
                            events.clear();
                            var manager =
                                    runtime.authenticationManagers()
                                            .resolve(
                                                    new org.springframework.mock.web
                                                            .MockHttpServletRequest());
                            manager.authenticate(
                                    new com.quantipixels.ogiri.security.internal
                                            .DtaAuthenticationToken(
                                            new com.quantipixels.ogiri.security.internal
                                                    .DtaCredential(
                                                    login.account().uid(),
                                                    login.issued().session().client(),
                                                    login.issued().token(),
                                                    false)));
                            manager.authenticate(
                                    new com.quantipixels.ogiri.security.internal
                                            .DtaAuthenticationToken(
                                            new com.quantipixels.ogiri.security.internal
                                                    .DtaCredential(
                                                    login.account().uid(),
                                                    login.issued().session().client(),
                                                    login.issued().token(),
                                                    false)));
                            assertThatThrownBy(
                                            () ->
                                                    manager.authenticate(
                                                            new com.quantipixels.ogiri.security
                                                                    .internal
                                                                    .DtaAuthenticationToken(
                                                                    new com.quantipixels.ogiri
                                                                            .security.internal
                                                                            .DtaCredential(
                                                                            "  TOKEN@example.test  ",
                                                                            login.issued()
                                                                                    .session()
                                                                                    .client(),
                                                                            "invalid-secret",
                                                                            false))))
                                    .isInstanceOf(
                                            org.springframework.security.authentication
                                                    .BadCredentialsException.class);
                            assertThat(events)
                                    .extracting(Object::getClass)
                                    .containsExactly(
                                            AuthenticationSuccessEvent.class,
                                            AuthenticationSuccessEvent.class,
                                            AuthenticationFailureBadCredentialsEvent.class);
                            assertThat(events)
                                    .allSatisfy(
                                            event -> {
                                                assertThat(
                                                                event.getAuthentication()
                                                                        .getCredentials())
                                                        .isNull();
                                                assertThat(event.getAuthentication().getPrincipal())
                                                        .isEqualTo(realm + ":token@example.test");
                                                assertSafe(
                                                        event,
                                                        "private-password",
                                                        "invalid-secret",
                                                        login.account().getPassword(),
                                                        login.issued().token(),
                                                        login.issued().session().client());
                                            });
                        });
    }

    @Test
    void unknownSignInPublishesNormalizedAttemptedIdentity() {
        runner().run(
                        context -> {
                            assertThatThrownBy(
                                            () ->
                                                    context.getBean(SignInService.class)
                                                            .signIn(
                                                                    "  UNKNOWN@example.test  ",
                                                                    "missing-password"))
                                    .isInstanceOf(DtaFailure.class);
                            assertThat(events)
                                    .singleElement()
                                    .satisfies(
                                            event -> {
                                                assertThat(event)
                                                        .isInstanceOf(
                                                                AuthenticationFailureBadCredentialsEvent
                                                                        .class);
                                                assertThat(event.getAuthentication().getPrincipal())
                                                        .isEqualTo("users:unknown@example.test");
                                                assertSafe(event, "missing-password");
                                            });
                        });
    }

    private static void assertSafe(AbstractAuthenticationEvent event, String... secrets) {
        assertThat(event.getAuthentication().getCredentials()).isNull();
        assertThat(event.getAuthentication().getDetails()).isNull();
        assertThat(event.toString()).doesNotContain(secrets);
        assertThat(event.getAuthentication().toString()).doesNotContain(secrets);
    }

    @Test
    void infrastructureLogsStackButNotDriverValues(CapturedOutput output) {
        runner().run(
                        context -> {
                            assertThatThrownBy(
                                            () ->
                                                    context.getBean(AuthTransactions.class)
                                                            .read(
                                                                    () -> {
                                                                        throw new org
                                                                                .springframework.dao
                                                                                .DataAccessResourceFailureException(
                                                                                "secret SQL password token@example.test");
                                                                    }))
                                    .isInstanceOf(SessionStoreException.class);
                            assertThat(output)
                                    .contains(
                                            "Ogiri authentication store unavailable",
                                            "DataAccessResourceFailureException",
                                            "OperationsTest")
                                    .doesNotContain("secret SQL password token@example.test");
                        });
    }

    @Test
    void schedulerRunsBoundedCleanupAndStops() throws Exception {
        var calls = new java.util.concurrent.CountDownLatch(1);
        var worker = new java.util.concurrent.atomic.AtomicReference<Thread>();
        var sessions =
                org.mockito.Mockito.mock(com.quantipixels.ogiri.internal.SessionRepository.class);
        org.mockito.Mockito.when(sessions.cleanup(2))
                .thenAnswer(
                        invocation -> {
                            worker.set(Thread.currentThread());
                            calls.countDown();
                            return 0;
                        });
        runner().withBean(com.quantipixels.ogiri.internal.SessionRepository.class, () -> sessions)
                .withPropertyValues("ogiri.cleanup.interval=20ms", "ogiri.cleanup.batch-size=2")
                .run(
                        context -> {
                            assertThat(context).hasNotFailed();
                            assertThat(calls.await(5, java.util.concurrent.TimeUnit.SECONDS))
                                    .isTrue();
                        });
        worker.get().join(5000);
        assertThat(worker.get().isAlive()).isFalse();
    }

    @Test
    void cleanupSchedulerIsOptInAndClosesWithContext() {
        runner().run(context -> assertThat(context).doesNotHaveBean("ogiriCleanupScheduler"));
        runner().withPropertyValues("ogiri.cleanup.interval=1h", "ogiri.cleanup.batch-size=2")
                .run(
                        context ->
                                assertThat(context)
                                        .hasNotFailed()
                                        .hasBean("ogiriCleanupScheduler"));
    }
}
