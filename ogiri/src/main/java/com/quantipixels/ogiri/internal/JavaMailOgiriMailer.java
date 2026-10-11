// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.internal;

import com.quantipixels.ogiri.mail.OgiriMailer;
import java.util.Locale;
import org.springframework.context.MessageSource;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

public final class JavaMailOgiriMailer implements OgiriMailer {
    private final JavaMailSender sender;
    private final MessageSource messages;
    private final String from;

    public JavaMailOgiriMailer(JavaMailSender sender, MessageSource messages, String from) {
        this.sender = sender;
        this.messages = messages;
        this.from = from;
    }

    @Override
    public void resetPassword(String recipient, String link) {
        send("reset", "Reset password", recipient, link);
    }

    @Override
    public void confirmation(String recipient, String link) {
        send("confirmation", "Confirmation instructions", recipient, link);
    }

    @Override
    public void unlock(String recipient, String link) {
        send("unlock", "Unlock instructions", recipient, link);
    }

    private void send(String kind, String subject, String recipient, String link) {
        var mail = new SimpleMailMessage();
        mail.setFrom(from);
        mail.setTo(recipient);
        mail.setSubject(
                messages.getMessage(
                        "ogiri.mail." + kind + ".subject", null, subject, Locale.ENGLISH));
        mail.setText(
                messages.getMessage(
                        "ogiri.mail." + kind + ".body",
                        new Object[] {link},
                        "Follow this link: {0}",
                        Locale.ENGLISH));
        sender.send(mail);
    }
}
