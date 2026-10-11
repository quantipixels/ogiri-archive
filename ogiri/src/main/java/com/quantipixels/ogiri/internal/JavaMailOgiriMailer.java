// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.internal;

import com.quantipixels.ogiri.mail.OgiriMailer;
import java.util.Locale;
import org.springframework.context.MessageSource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;

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
        try {
            var message = sender.createMimeMessage();
            var mail = new MimeMessageHelper(message, true, "UTF-8");
            mail.setFrom(from);
            mail.setTo(recipient);
            mail.setSubject(
                    messages.getMessage(
                            "ogiri.mail." + kind + ".subject", null, subject, Locale.ENGLISH));
            String text =
                    messages.getMessage(
                            "ogiri.mail." + kind + ".body",
                            new Object[] {link},
                            "Follow this link: {0}",
                            Locale.ENGLISH);
            String escaped = org.springframework.web.util.HtmlUtils.htmlEscape(link);
            String html =
                    messages.getMessage(
                            "ogiri.mail." + kind + ".html",
                            new Object[] {escaped},
                            "<a href=\"{0}\">Follow this link</a>",
                            Locale.ENGLISH);
            mail.setText(text, html);
            sender.send(message);
        } catch (jakarta.mail.MessagingException failure) {
            throw new org.springframework.mail.MailPreparationException(
                    "Unable to prepare Ogiri mail", failure);
        }
    }
}
