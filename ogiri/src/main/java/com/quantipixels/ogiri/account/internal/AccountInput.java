// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account.internal;

import java.util.LinkedHashMap;
import java.util.Map;

/** Permitted account data, shared by JSON and form requests. */
public record AccountInput(
        @jakarta.validation.constraints.Pattern(
                        regexp = "[^@\\s]+@[^@\\s]+",
                        message = "is not an email")
                String email,
        @CodePointLength String password,
        String password_confirmation,
        String current_password,
        Map<String, Object> attributes,
        boolean registration) {
    public AccountInput {
        attributes = java.util.Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
    }

    public static AccountInput from(
            Map<String, ?> input, OgiriSettings settings, boolean registration) {
        var extra = new LinkedHashMap<String, Object>();
        for (String field : settings.permittedFields()) {
            if (input.containsKey(field)) extra.put(field, input.get(field));
        }
        String email = text(input, "email");
        return new AccountInput(
                email == null ? null : JdbcDeviseAccountStore.normalize(email),
                text(input, "password"),
                text(input, "password_confirmation"),
                text(input, "current_password"),
                java.util.Collections.unmodifiableMap(extra),
                registration);
    }

    public boolean empty() {
        return email == null
                && password == null
                && password_confirmation == null
                && current_password == null
                && attributes.isEmpty();
    }

    private static String text(Map<String, ?> input, String key) {
        Object value = input.get(key);
        return value instanceof String text ? text : null;
    }

    @Override
    public String toString() {
        return "AccountInput[redacted]";
    }
}
