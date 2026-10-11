// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.internal;

import com.quantipixels.ogiri.DtaFailure;
import com.quantipixels.ogiri.mail.OgiriMailer;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/** Receipts convey AFTER_COMMIT delivery failure without rolling back committed credentials. */
public final class MailDispatcher {
    public enum Kind {
        RESET,
        CONFIRMATION,
        UNLOCK
    }

    private final ApplicationEventPublisher events;
    private final OgiriMailer mailer;

    public MailDispatcher(ApplicationEventPublisher events, OgiriMailer mailer) {
        this.events = events;
        this.mailer = mailer;
    }

    public static final class Receipt {
        private boolean delivered;

        public void verify(boolean paranoid) {
            if (!delivered && !paranoid) throw new DtaFailure(503, DtaFailure.unavailable());
        }
    }

    public record Intent(Kind kind, String recipient, String link, Receipt receipt) {
        @Override
        public String toString() {
            return "OgiriMailIntent[redacted]";
        }
    }

    public Receipt enqueue(Kind kind, String recipient, String link) {
        var receipt = new Receipt();
        events.publishEvent(new Intent(kind, recipient, link, receipt));
        return receipt;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void deliver(Intent intent) {
        try {
            switch (intent.kind()) {
                case RESET -> mailer.resetPassword(intent.recipient(), intent.link());
                case CONFIRMATION -> mailer.confirmation(intent.recipient(), intent.link());
                case UNLOCK -> mailer.unlock(intent.recipient(), intent.link());
            }
            intent.receipt().delivered = true;
        } catch (Exception failure) {
            org.apache.commons.logging.LogFactory.getLog(MailDispatcher.class)
                    .warn("Ogiri mail delivery failed (" + intent.kind() + ")");
        }
    }
}
