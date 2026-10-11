// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri;

import java.util.Objects;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.TransactionAwareDataSourceProxy;
import org.springframework.jdbc.support.JdbcTransactionManager;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionTemplate;

/** One resource and lock owner for atomic, independently committed auth operations. */
public final class AuthTransactions {
    private final JdbcTemplate jdbc;
    private final Database database;
    private final TransactionTemplate mutations;
    private final TransactionTemplate reads;

    public AuthTransactions(DataSource source) {
        this(source, defaultManager(source));
    }

    @SuppressWarnings(
            "ReferenceEquality") // Transaction resource identity, not logical DataSource equality.
    public AuthTransactions(DataSource source, PlatformTransactionManager manager) {
        Objects.requireNonNull(source, "source");
        if (source instanceof TransactionAwareDataSourceProxy) {
            throw new IllegalArgumentException(
                    "Supply the underlying DataSource, not TransactionAwareDataSourceProxy");
        }
        DataSource managed;
        if (manager instanceof DataSourceTransactionManager jdbcManager) {
            managed = jdbcManager.getDataSource();
        } else if (manager instanceof JpaTransactionManager jpaManager) {
            managed = jpaManager.getDataSource();
        } else {
            throw new IllegalArgumentException("Ogiri requires a JDBC or JPA transaction manager");
        }
        if (managed != source) {
            throw new IllegalArgumentException(
                    "Ogiri's transaction manager must manage the configured DataSource");
        }
        database = Database.detect(source);
        jdbc = new JdbcTemplate(source);
        jdbc.setQueryTimeout(5);
        mutations = new TransactionTemplate(manager);
        mutations.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        mutations.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
        mutations.setTimeout(10);
        reads = new TransactionTemplate(manager);
        reads.setPropagationBehavior(TransactionDefinition.PROPAGATION_NOT_SUPPORTED);
    }

    private static JdbcTransactionManager defaultManager(DataSource source) {
        var manager = new JdbcTransactionManager(source);
        manager.setRollbackOnCommitFailure(true);
        return manager;
    }

    String clockExpression() {
        return database.now;
    }

    public JdbcTemplate jdbc() {
        return jdbc;
    }

    public long now() {
        return Objects.requireNonNull(jdbc.queryForObject("SELECT " + database.now, Long.class));
    }

    public void lock(Subject subject) {
        byte[] key = Tokens.lockKey(subject);
        jdbc.update(database.insertLock, key);
        jdbc.queryForObject(
                "SELECT lock_key FROM ogiri_subject_locks WHERE lock_key = ? FOR UPDATE",
                byte[].class,
                key);
    }

    public <T> T write(Supplier<T> operation) {
        return execute(mutations, operation);
    }

    public <T> T read(Supplier<T> operation) {
        return execute(reads, operation);
    }

    private static <T> T execute(TransactionTemplate template, Supplier<T> operation) {
        try {
            return template.execute(status -> operation.get());
        } catch (DataAccessException | TransactionException failure) {
            throw new SessionStoreException(failure);
        }
    }
}
