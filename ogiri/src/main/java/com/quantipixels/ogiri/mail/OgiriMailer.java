// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.mail;

/** Replace this bean to customize mail content or delivery. */
public interface OgiriMailer {
    void resetPassword(String recipient, String link);

    void confirmation(String recipient, String link);

    void unlock(String recipient, String link);
}
