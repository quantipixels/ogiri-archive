// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.spring;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.quantipixels.ogiri.account.AccountStore;
import com.quantipixels.ogiri.account.OgiriAccount;
import com.quantipixels.ogiri.account.internal.AccountValidator;
import com.quantipixels.ogiri.account.internal.DevisePasswordEncoder;
import com.quantipixels.ogiri.account.internal.OgiriSettings;
import com.quantipixels.ogiri.account.internal.PasswordService;
import com.quantipixels.ogiri.account.internal.SignInService;
import com.quantipixels.ogiri.internal.AuthTransactions;
import com.quantipixels.ogiri.internal.DtaFailure;
import com.quantipixels.ogiri.internal.SessionRepository;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TypedAccountStoreTest {
    @ParameterizedTest
    @ValueSource(strings = {"absent", "", "email", "github"})
    void passwordChangeHandlesOptionalProvider(String provider) {
        var columns = new java.util.LinkedHashMap<String, Object>();
        columns.put("id", "custom-account");
        columns.put("ogiri_generation", "incarnation-1");
        if (!provider.equals("absent")) columns.put("provider", provider);
        var account = new OgiriAccount(columns, List.of());
        var accounts = mock(AccountStore.class);
        var transactions = mock(AuthTransactions.class);
        var sessions = mock(SessionRepository.class);
        var settings = OgiriSettings.defaults();
        var encoder = new DevisePasswordEncoder(4);
        var signIn = new SignInService(accounts, transactions, sessions, settings, encoder, null);
        when(transactions.write(any())).thenAnswer(call -> call.<Supplier<?>>getArgument(0).get());
        when(accounts.lock(account.id())).thenReturn(Optional.of(account));
        when(accounts.update(eq(account.id()), anyMap())).thenReturn(account);
        var passwords =
                new PasswordService(
                        accounts,
                        transactions,
                        sessions,
                        settings,
                        encoder,
                        signIn,
                        mock(AccountValidator.class),
                        null,
                        null);
        var session =
                new com.quantipixels.ogiri.Session(
                        java.util.UUID.randomUUID(),
                        settings.subject(account),
                        "client",
                        java.time.Instant.now(),
                        java.time.Instant.now().plusSeconds(3600));
        var values =
                Map.of("password", "changed-password", "password_confirmation", "changed-password");
        if (provider.equals("github")) {
            var failure =
                    assertThrows(
                            DtaFailure.class, () -> passwords.change(account, values, session));
            assertEquals(422, failure.status());
            assertTrue(failure.body().toString().contains("Github"));
            verify(accounts, never()).update(anyString(), anyMap());
        } else {
            assertDoesNotThrow(() -> passwords.change(account, values, session));
            verify(accounts)
                    .update(
                            eq(account.id()),
                            argThat(
                                    changes ->
                                            encoder.matches(
                                                    "changed-password",
                                                    (String) changes.get("encrypted_password"))));
        }
    }
}
