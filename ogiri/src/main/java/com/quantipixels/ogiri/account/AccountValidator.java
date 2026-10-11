// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

/** Devise validation messages; lengths count Unicode code points, not UTF-16 units. */
public final class AccountValidator implements Validator {
    private final org.springframework.validation.beanvalidation.SpringValidatorAdapter
            beanValidation;

    public AccountValidator(jakarta.validation.Validator validator) {
        beanValidation =
                new org.springframework.validation.beanvalidation.SpringValidatorAdapter(validator);
    }

    @Override
    public boolean supports(Class<?> type) {
        return AccountInput.class.equals(type);
    }

    @Override
    public void validate(Object target, Errors errors) {
        var input = (AccountInput) target;
        beanValidation.validate(input, errors);
        validateEmail(input, errors);
        validatePassword(input, errors);
    }

    private static void validateEmail(AccountInput input, Errors errors) {
        if (input.registration() && input.email() == null)
            errors.rejectValue("email", "email", "is not an email");
    }

    private static void validatePassword(AccountInput input, Errors errors) {
        if (input.registration() && input.password() == null)
            errors.rejectValue("password", "blank", "can't be blank");
        if (input.password_confirmation() != null
                && !input.password_confirmation().equals(input.password()))
            errors.rejectValue("password_confirmation", "confirmation", "doesn't match Password");
    }

    public static Map<String, Object> messages(Errors errors) {
        var fields = new LinkedHashMap<String, Object>();
        var full = new ArrayList<String>();
        var grouped = new LinkedHashMap<String, List<String>>();
        for (var error : errors.getFieldErrors()) {
            String message = error.getDefaultMessage();
            grouped.computeIfAbsent(error.getField(), key -> new ArrayList<>()).add(message);
            String label = error.getField().replace('_', ' ');
            full.add(Character.toUpperCase(label.charAt(0)) + label.substring(1) + " " + message);
        }
        fields.putAll(grouped);
        fields.put("full_messages", full);
        return fields;
    }
}
