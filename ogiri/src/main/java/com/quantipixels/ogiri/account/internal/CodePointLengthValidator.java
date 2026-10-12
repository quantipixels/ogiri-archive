// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account.internal;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public final class CodePointLengthValidator
        implements ConstraintValidator<CodePointLength, String> {
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null) return true;
        int length = value.codePointCount(0, value.length());
        if (length >= 6 && length <= 128) return true;
        String message =
                length == 0
                        ? "can't be blank"
                        : length < 6
                                ? "is too short (minimum is 6 characters)"
                                : "is too long (maximum is 128 characters)";
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(message).addConstraintViolation();
        return false;
    }
}
