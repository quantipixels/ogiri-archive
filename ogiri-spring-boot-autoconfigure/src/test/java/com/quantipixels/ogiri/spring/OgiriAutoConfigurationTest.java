// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.quantipixels.ogiri.JdbcSessions;
import com.quantipixels.ogiri.account.OgiriSettings;
import com.quantipixels.ogiri.internal.AuthTransactions;
import javax.sql.DataSource;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.support.JdbcTransactionManager;
import org.springframework.orm.jpa.JpaTransactionManager;

class OgiriAutoConfigurationTest {
    private final WebApplicationContextRunner runner =
            new WebApplicationContextRunner()
                    .withConfiguration(AutoConfigurations.of(OgiriAutoConfiguration.class))
                    .withBean(
                            org.springframework.mail.javamail.JavaMailSender.class,
                            org.springframework.mail.javamail.JavaMailSenderImpl::new)
                    .withPropertyValues("ogiri.public-base-url=https://accounts.example.test");

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(
            strings = {
                "id",
                "uid",
                "email",
                "provider",
                "ogiri_generation",
                "encrypted_password",
                "password",
                "password_confirmation",
                "current_password",
                "tokens",
                "reset_password_token",
                "reset_password_sent_at",
                "allow_password_change",
                "remember_created_at",
                "confirmation_token",
                "confirmed_at",
                "confirmation_sent_at",
                "unconfirmed_email",
                "failed_attempts",
                "unlock_token",
                "locked_at",
                "sign_in_count",
                "current_sign_in_at",
                "last_sign_in_at",
                "current_sign_in_ip",
                "last_sign_in_ip",
                "created_at",
                "updated_at",
                "ENCRYPTED_PASSWORD",
                "Provider",
                "CONFIRMED_AT"
            })
    @Tag("database")
    void reservedPermittedFieldsFailAtStartup(String field) {
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .withPropertyValues("ogiri.permitted-fields=" + field)
                .run(
                        context ->
                                assertThat(context.getStartupFailure())
                                        .hasRootCauseMessage(
                                                "ogiri.permitted-fields cannot include reserved account column: "
                                                        + field));
    }

    @Test
    @Tag("database")
    void additionalRealmRejectsReservedFieldsAndCustomBusinessFieldsRemainAllowed() {
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .withPropertyValues(
                        "ogiri.permitted-fields=department",
                        "ogiri.realms.admins.base-path=/admin_auth",
                        "ogiri.realms.admins.account.table=admins",
                        "ogiri.realms.admins.permitted-fields=locked_at")
                .run(
                        context ->
                                assertThat(context.getStartupFailure())
                                        .hasRootCauseMessage(
                                                "ogiri.permitted-fields cannot include reserved account column: locked_at"));
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .withPropertyValues("ogiri.permitted-fields=department")
                .run(
                        context -> {
                            assertThat(context).hasNotFailed();
                            var input =
                                    com.quantipixels.ogiri.account.AccountInput.from(
                                            java.util.Map.of("department", "engineering"),
                                            context.getBean(OgiriSettings.class),
                                            false);
                            assertThat(input.attributes())
                                    .containsEntry("department", "engineering");
                        });
    }

    private static DataSource source() {
        if (System.getenv("OGIRI_TEST_JDBC_URL") == null) {
            return new DriverManagerDataSource();
        }
        return new DriverManagerDataSource(
                System.getenv("OGIRI_TEST_JDBC_URL"),
                System.getenv("OGIRI_TEST_JDBC_USER"),
                System.getenv("OGIRI_TEST_JDBC_PASSWORD"));
    }

    @Test
    @Tag("database")
    void defaultChainDoesNotEnableCorsWithoutHostConfiguration() {
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .run(
                        context -> {
                            assertThat(context).hasNotFailed();
                            assertThat(
                                            context.getBean(
                                                            org.springframework.security.web
                                                                    .SecurityFilterChain.class)
                                                    .getFilters())
                                    .noneMatch(
                                            filter ->
                                                    filter
                                                            instanceof
                                                            org.springframework.web.filter
                                                                    .CorsFilter);
                        });
    }

    @Test
    @Tag("database")
    void missingMailFailsWithActionableCause() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(OgiriAutoConfiguration.class))
                .withPropertyValues("ogiri.public-base-url=https://accounts.example.test")
                .withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .run(
                        context ->
                                assertThat(context.getStartupFailure())
                                        .hasRootCauseMessage(
                                                "Ogiri password recovery requires JavaMailSender or OgiriMailer"));
    }

    @Test
    void noDataSourceMeansNoAuthInfrastructure() {
        runner.run(
                context ->
                        assertThat(context).hasNotFailed().doesNotHaveBean(AuthTransactions.class));
    }

    @Test
    void explicitDisableLeavesTheHostAlone() {
        runner.withPropertyValues("ogiri.enabled=false")
                .withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .run(
                        context ->
                                assertThat(context)
                                        .hasNotFailed()
                                        .doesNotHaveBean(JdbcSessions.class));
    }

    @Test
    @Tag("database")
    void dataSourcePresenceEnablesDtaDefaults() {
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .run(
                        context -> {
                            assertThat(context).hasNotFailed().hasSingleBean(JdbcSessions.class);
                            assertThat(context.getBean(OgiriSettings.class).tokenLifespan())
                                    .isEqualTo(java.time.Duration.ofDays(14));
                        });
    }

    @Test
    @Tag("database")
    void invalidMountFailsWithTheCause() {
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .withPropertyValues("ogiri.base-path=/auth/**")
                .run(
                        context ->
                                assertThat(context.getStartupFailure())
                                        .hasRootCauseMessage(
                                                "ogiri.base-path must be a canonical literal absolute path"));
    }

    @Test
    @Tag("database")
    void jdbcResourceMismatchIsRejected() {
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .withBean(
                        "foreign",
                        org.springframework.transaction.PlatformTransactionManager.class,
                        () -> new JdbcTransactionManager(source()))
                .run(
                        context ->
                                assertThat(context.getStartupFailure())
                                        .hasRootCauseMessage(
                                                "Ogiri's transaction manager must manage the configured DataSource"));
    }

    @Test
    void jpaResourceMismatchIsRejectedBeforeIssuingAnySessions() {
        var source = source();
        var manager = new JpaTransactionManager();
        manager.setDataSource(source());
        org.junit.jupiter.api.Assertions.assertEquals(
                "Ogiri's transaction manager must manage the configured DataSource",
                org.junit.jupiter.api.Assertions.assertThrows(
                                IllegalArgumentException.class,
                                () -> new AuthTransactions(source, manager))
                        .getMessage());
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
        "ogiri.cleanup.interval=1m,Ogiri scheduled cleanup is not implemented in this checkpoint"
    })
    void unfinishedConfiguredBehaviorFailsExplicitly(String property, String cause) {
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .withPropertyValues(property)
                .run(context -> assertThat(context.getStartupFailure()).hasRootCauseMessage(cause));
    }

    @Test
    @Tag("database")
    void cookieScopesMustNotCollideAndCsrfCookieNameIsReserved() {
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .withPropertyValues("ogiri.cookie-enabled=true", "ogiri.cookie-name=XSRF-TOKEN")
                .run(
                        context ->
                                assertThat(context.getStartupFailure())
                                        .hasRootCauseMessage(
                                                "Ogiri auth cookie name must differ from XSRF-TOKEN"));
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .withPropertyValues(
                        "ogiri.cookie-enabled=true",
                        "ogiri.realms.admins.base-path=/admin_auth",
                        "ogiri.realms.admins.account.table=admins")
                .run(
                        context ->
                                assertThat(context.getStartupFailure())
                                        .hasRootCauseMessage(
                                                "Ogiri realm cookies require distinct names or non-overlapping paths"));
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .withPropertyValues(
                        "ogiri.cookie-enabled=true",
                        "ogiri.realms.admins.base-path=/admin_auth",
                        "ogiri.realms.admins.account.table=admins",
                        "ogiri.realms.admins.cookie-name=admin_auth_cookie")
                .run(context -> assertThat(context).hasNotFailed());
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .withPropertyValues(
                        "ogiri.cookie-enabled=true",
                        "ogiri.cookie-path=/auth",
                        "ogiri.realms.admins.base-path=/admin_auth",
                        "ogiri.realms.admins.account.table=admins",
                        "ogiri.realms.admins.cookie-path=/admin_auth")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    @Tag("database")
    void overlappingRealmMountsFailBeforeServingRequests() {
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .withPropertyValues(
                        "ogiri.realms.admins.base-path=/auth/admins",
                        "ogiri.realms.admins.account.table=admins")
                .run(
                        context ->
                                assertThat(context.getStartupFailure())
                                        .hasRootCauseMessage(
                                                "Ogiri realm names and mounts must be distinct and non-overlapping"));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"users", "admins"})
    @Tag("database")
    void duplicateRealmTablesFailBeforeServingRequests(String table) {
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .withPropertyValues(
                        "ogiri.realms.admins.base-path=/admin_auth",
                        "ogiri.realms.staff.base-path=/staff_auth",
                        "ogiri.realms.staff.account.table=" + table)
                .withPropertyValues(
                        table.equals("admins")
                                ? "ogiri.realms.admins.account.table=admins"
                                : "ogiri.account.table=users")
                .run(
                        context ->
                                assertThat(context.getStartupFailure())
                                        .hasRootCauseMessage(
                                                "Ogiri realms must use distinct account tables; configure ogiri.realms."
                                                        + (table.equals("users")
                                                                ? "admins"
                                                                : "staff")
                                                        + ".account.table or an explicit "
                                                        + (table.equals("users")
                                                                ? "admins"
                                                                : "staff")
                                                        + "OgiriAccountStore bean"));
    }

    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    static class SingleRuntimeChain {
        @org.springframework.context.annotation.Bean
        org.springframework.security.web.SecurityFilterChain hostChain(
                org.springframework.security.config.annotation.web.builders.HttpSecurity http,
                com.quantipixels.ogiri.security.OgiriRuntime runtime)
                throws Exception {
            http.with(com.quantipixels.ogiri.security.OgiriConfigurer.ogiri(runtime), config -> {});
            return http.authorizeHttpRequests(routes -> routes.anyRequest().permitAll()).build();
        }
    }

    @Test
    @Tag("database")
    void singleRuntimeChainRefusesAdditionalRealmMounts() {
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .withUserConfiguration(SingleRuntimeChain.class)
                .withPropertyValues(
                        "ogiri.realms.admins.base-path=/admin_auth",
                        "ogiri.realms.admins.account.table=admins")
                .run(
                        context ->
                                assertThat(context.getStartupFailure())
                                        .hasRootCauseMessage(
                                                "OgiriConfigurer.ogiri(runtime) cannot be used with additional realms; use OgiriConfigurer.ogiri(realms)"));
    }

    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    static class RealmStoreConfiguration {
        @org.springframework.context.annotation.Bean(defaultCandidate = false)
        com.quantipixels.ogiri.account.AccountStore adminsOgiriAccountStore(
                AuthTransactions transactions) {
            return new com.quantipixels.ogiri.account.JdbcDeviseAccountStore(
                    transactions, "admins", columns -> java.util.List.of());
        }
    }

    @Test
    @Tag("database")
    void realmStoreDoesNotReplaceTheRootStore() {
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .withUserConfiguration(RealmStoreConfiguration.class)
                .withPropertyValues("ogiri.realms.admins.base-path=/admin_auth")
                .run(
                        context -> {
                            assertThat(context).hasNotFailed();
                            var realms =
                                    context.getBean(
                                            com.quantipixels.ogiri.security.OgiriRealms.class);
                            assertThat(realms.additional().get(0).accounts())
                                    .isSameAs(context.getBean("adminsOgiriAccountStore"));
                            assertThat(realms.defaultRealm().accounts())
                                    .isNotSameAs(realms.additional().get(0).accounts());
                        });
    }
}
