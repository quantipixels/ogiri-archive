// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.quantipixels.ogiri.account.AccountStore;
import com.quantipixels.ogiri.account.OgiriAccount;
import com.quantipixels.ogiri.internal.AuthTransactions;
import com.quantipixels.ogiri.mail.OgiriMailer;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

class RealmOverridesTest {
    @Configuration(proxyBeanMethods = false)
    static class Overrides {
        @Bean(defaultCandidate = false)
        AccountStore adminsOgiriAccountStore() {
            return store("admin@example.test");
        }

        @Bean(defaultCandidate = false)
        OgiriMailer adminsOgiriMailer() {
            return mock(OgiriMailer.class);
        }

        @Bean(defaultCandidate = false)
        com.quantipixels.ogiri.account.internal.OgiriPasswords adminsOgiriPasswordEncoder() {
            return new com.quantipixels.ogiri.account.internal.OgiriPasswords(
                    spy(new com.quantipixels.ogiri.account.internal.DevisePasswordEncoder(4)));
        }

        @Bean(defaultCandidate = false)
        com.quantipixels.ogiri.account.internal.AccountValidator adminsOgiriAccountValidator(
                jakarta.validation.Validator validator) {
            return spy(new com.quantipixels.ogiri.account.internal.AccountValidator(validator));
        }
    }

    private static AccountStore store(String email) {
        var store = mock(AccountStore.class);
        var account = new OgiriAccount(Map.of("id", "1", "email", email, "uid", email), List.of());
        when(store.findByEmail(email)).thenReturn(Optional.of(account));
        when(store.lock("1")).thenReturn(Optional.of(account));
        when(store.preview(any())).thenReturn(account);
        return store;
    }

    private static AuthTransactions transactions() {
        var transactions = mock(AuthTransactions.class);
        when(transactions.jdbc())
                .thenReturn(mock(org.springframework.jdbc.core.JdbcTemplate.class));
        when(transactions.read(any()))
                .thenAnswer(call -> ((Supplier<?>) call.getArgument(0)).get());
        when(transactions.write(any()))
                .thenAnswer(
                        call -> {
                            TransactionSynchronizationManager.initSynchronization();
                            TransactionSynchronizationManager.setActualTransactionActive(true);
                            try {
                                var result = ((Supplier<?>) call.getArgument(0)).get();
                                for (var listener :
                                        TransactionSynchronizationManager.getSynchronizations()) {
                                    listener.afterCommit();
                                    listener.afterCompletion(
                                            TransactionSynchronization.STATUS_COMMITTED);
                                }
                                return result;
                            } finally {
                                TransactionSynchronizationManager.clear();
                            }
                        });
        return transactions;
    }

    @Test
    void additionalRealmEndpointsUseTheirStoreAndMailer() {
        var sharedMailer = mock(OgiriMailer.class);
        var sharedStore = store("user@example.test");
        new WebApplicationContextRunner()
                .withConfiguration(
                        AutoConfigurations.of(
                                OgiriAutoConfiguration.class,
                                org.springframework.boot.webmvc.autoconfigure
                                        .WebMvcAutoConfiguration.class,
                                org.springframework.boot.validation.autoconfigure
                                        .ValidationAutoConfiguration.class))
                .withUserConfiguration(Overrides.class)
                .withBean(DataSource.class, () -> mock(DataSource.class))
                .withBean(AuthTransactions.class, RealmOverridesTest::transactions)
                .withBean("sharedStore", AccountStore.class, () -> sharedStore)
                .withBean("sharedMailer", OgiriMailer.class, () -> sharedMailer)
                .withPropertyValues(
                        "ogiri.bcrypt-cost=4",
                        "ogiri.public-base-url=https://accounts.example.test",
                        "ogiri.redirect-allowlist=https://app.example.test/reset",
                        "ogiri.realms.admins.base-path=/admin_auth",
                        "ogiri.token-lifespan=2d",
                        "ogiri.realms.admins.max-number-of-devices=3",
                        "ogiri.realms.staff.base-path=/staff_auth")
                .run(
                        context -> {
                            assertThat(context).hasNotFailed();
                            var mvc = MockMvcBuilders.webAppContextSetup(context).build();
                            mvc.perform(
                                            post("/admin_auth/password")
                                                    .contentType("application/json")
                                                    .content(
                                                            "{\"email\":\"admin@example.test\",\"redirect_url\":\"https://app.example.test/reset\"}"))
                                    .andExpect(status().isOk());
                            verify(context.getBean("adminsOgiriAccountStore", AccountStore.class))
                                    .findByEmail("admin@example.test");
                            verify(context.getBean("adminsOgiriMailer", OgiriMailer.class))
                                    .resetPassword(eq("admin@example.test"), any());
                            verifyNoInteractions(sharedMailer, sharedStore);
                            mvc.perform(
                                            post("/auth/password")
                                                    .contentType("application/json")
                                                    .content(
                                                            "{\"email\":\"user@example.test\",\"redirect_url\":\"https://app.example.test/reset\"}"))
                                    .andExpect(status().isOk());
                            mvc.perform(
                                            post("/staff_auth/password")
                                                    .contentType(
                                                            "application/x-www-form-urlencoded")
                                                    .param("email", "user@example.test")
                                                    .param(
                                                            "redirect_url",
                                                            "https://app.example.test/reset"))
                                    .andExpect(status().isOk());
                            verify(sharedMailer, times(2))
                                    .resetPassword(eq("user@example.test"), any());
                            verify(
                                            context.getBean("adminsOgiriMailer", OgiriMailer.class),
                                            times(1))
                                    .resetPassword(any(), any());
                            var realm =
                                    context.getBean(
                                                    com.quantipixels.ogiri.security.OgiriRealms
                                                            .class)
                                            .additional()
                                            .get(0);
                            assertThat(realm.settings().tokenLifespan())
                                    .isEqualTo(java.time.Duration.ofDays(2));
                            assertThat(realm.settings().maxNumberOfDevices()).isEqualTo(3);
                            assertThat(
                                            context.getBean(OgiriProperties.class)
                                                    .realms()
                                                    .get("admins")
                                                    .basePath())
                                    .isEqualTo("/admin_auth");
                            mvc.perform(
                                            post("/admin_auth/sign_in")
                                                    .contentType("application/json")
                                                    .content(
                                                            "{\"email\":\"admin@example.test\",\"password\":\"wrong-password\"}"))
                                    .andExpect(status().isUnauthorized());
                            verify(
                                            context.getBean(
                                                            "adminsOgiriPasswordEncoder",
                                                            com.quantipixels.ogiri.account.internal
                                                                    .OgiriPasswords.class)
                                                    .encoder())
                                    .matches(eq("wrong-password"), any());
                            mvc.perform(
                                            post("/admin_auth")
                                                    .contentType("application/json")
                                                    .content(
                                                            "{\"email\":\"invalid\",\"password\":\"test-password\"}"))
                                    .andExpect(status().isUnprocessableContent());
                            verify(
                                            context.getBean(
                                                    "adminsOgiriAccountValidator",
                                                    com.quantipixels.ogiri.account.internal
                                                            .AccountValidator.class))
                                    .validate(any(), any());
                        });
    }

    @org.springframework.web.bind.annotation.RestController
    static class HostController {
        @org.springframework.web.bind.annotation.GetMapping("/admin_auth/password")
        String password() {
            return "host";
        }
    }

    @Test
    void existingHostPathFailsBeforeServingRealmRequests() {
        new WebApplicationContextRunner()
                .withConfiguration(
                        AutoConfigurations.of(
                                OgiriAutoConfiguration.class,
                                org.springframework.boot.webmvc.autoconfigure
                                        .WebMvcAutoConfiguration.class,
                                org.springframework.boot.validation.autoconfigure
                                        .ValidationAutoConfiguration.class))
                .withUserConfiguration(Overrides.class, HostController.class)
                .withBean(DataSource.class, () -> mock(DataSource.class))
                .withBean(AuthTransactions.class, RealmOverridesTest::transactions)
                .withBean("sharedStore", AccountStore.class, () -> store("user@example.test"))
                .withBean("sharedMailer", OgiriMailer.class, () -> mock(OgiriMailer.class))
                .withPropertyValues(
                        "ogiri.bcrypt-cost=4",
                        "ogiri.public-base-url=https://accounts.example.test",
                        "ogiri.realms.admins.base-path=/admin_auth")
                .run(
                        context ->
                                assertThat(context.getStartupFailure())
                                        .hasMessageContaining(
                                                "Duplicate Ogiri realm endpoint path: /admin_auth/password"));
    }
}
