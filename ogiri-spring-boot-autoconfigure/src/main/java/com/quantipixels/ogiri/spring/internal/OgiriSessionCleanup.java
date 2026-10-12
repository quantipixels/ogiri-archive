// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.spring.internal;

import com.quantipixels.ogiri.JdbcSessions;
import com.quantipixels.ogiri.SessionStoreException;
import com.quantipixels.ogiri.spring.OgiriProperties;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

/** Owns its scheduler without replacing the application's scheduling infrastructure. */
public final class OgiriSessionCleanup implements InitializingBean, DisposableBean {
    private static final Logger LOG = LoggerFactory.getLogger(OgiriSessionCleanup.class);
    private final ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
    private final JdbcSessions sessions;
    private final OgiriProperties.Cleanup settings;

    public OgiriSessionCleanup(JdbcSessions sessions, OgiriProperties.Cleanup settings) {
        this.sessions = sessions;
        this.settings = settings;
    }

    @Override
    public void afterPropertiesSet() {
        scheduler.setThreadNamePrefix("ogiri-cleanup-");
        scheduler.initialize();
        scheduler.scheduleWithFixedDelay(
                this::cleanup, Instant.now().plus(settings.interval()), settings.interval());
    }

    private void cleanup() {
        try {
            sessions.cleanup(settings.batchSize());
        } catch (SessionStoreException unavailable) {
            // AuthTransactions already logged a sanitized stack.
            LOG.warn("Ogiri cleanup deferred until next interval");
        }
    }

    @Override
    public void destroy() {
        scheduler.shutdown();
    }
}
