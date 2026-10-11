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
        "ogiri.cookie-enabled=true,Ogiri cookie login CSRF is not implemented in this checkpoint",
        "ogiri.cleanup.interval=1m,Ogiri scheduled cleanup is not implemented in this checkpoint"
    })
    void unfinishedConfiguredBehaviorFailsExplicitly(String property, String cause) {
        runner.withBean(DataSource.class, OgiriAutoConfigurationTest::source)
                .withPropertyValues(property)
                .run(context -> assertThat(context.getStartupFailure()).hasRootCauseMessage(cause));
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
                .withPropertyValues(
                        "ogiri.realms.admins.base-path=/admin_auth",
                        "ogiri.realms.admins.account.table=admins")
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
