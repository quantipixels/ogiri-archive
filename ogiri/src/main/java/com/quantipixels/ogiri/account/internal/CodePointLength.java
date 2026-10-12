// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account.internal;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = CodePointLengthValidator.class)
public @interface CodePointLength {
    String message() default "invalid password length";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
