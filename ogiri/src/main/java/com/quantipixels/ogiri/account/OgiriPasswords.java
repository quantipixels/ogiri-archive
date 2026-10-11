// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account;

/** Ogiri-only password policy; deliberately not a host PasswordEncoder bean. */
public record OgiriPasswords(DevisePasswordEncoder encoder) {}
