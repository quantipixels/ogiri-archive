// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import static org.junit.jupiter.api.Assertions.*;
import com.quantipixels.ogiri.*;
import jakarta.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.EntityManagerFactoryUtils;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest(properties = {
        "spring.datasource.url=${OGIRI_TEST_JDBC_URL}",
        "spring.datasource.username=${OGIRI_TEST_JDBC_USER}",
        "spring.datasource.password=${OGIRI_TEST_JDBC_PASSWORD}",
        "spring.datasource.hikari.maximum-pool-size=3", "spring.jpa.open-in-view=false",
        "spring.profiles.active=demo"
})
class JpaTransactionTest {
    @Autowired JdbcSessions sessions;
    @Autowired PlatformTransactionManager transactions;
    @Autowired EntityManagerFactory entityManagers;
    @Autowired DataSource source;

    @Test void nativeJpaTransactionsCannotUndoSessionChangesOrRetainStaleAuthentication() {
        assertInstanceOf(JpaTransactionManager.class, transactions);
        var owner = new Subject("users", "", "jpa-contract");
        sessions.revokeAll(owner);
        var jdbc = new JdbcTemplate(source);
        var outside = sessions.issue(owner, "before transaction");
        var outer = new TransactionTemplate(transactions);
        outer.setIsolationLevel(org.springframework.transaction.TransactionDefinition.ISOLATION_REPEATABLE_READ);
        var survivor = outer.execute(status -> {
            var em = EntityManagerFactoryUtils.getTransactionalEntityManager(entityManagers);
            assertNotNull(em);
            em.createNativeQuery("SELECT count(*) FROM ogiri_sessions").getSingleResult();
            assertTrue(sessions.authenticate(outside.token()).isPresent());
            assertTrue(sessions.revoke(owner, outside.session().id()));
            assertTrue(sessions.authenticate(outside.token()).isEmpty(), "Must not reuse the host's repeatable-read snapshot");
            var committed = sessions.issue(owner, "independent");
            assertSame(em, EntityManagerFactoryUtils.getTransactionalEntityManager(entityManagers));
            // This application write must still roll back after Ogiri resumes the original JPA transaction.
            jdbc.update("UPDATE ogiri_sessions SET client = ? WHERE id = ?", "host rollback", committed.session().id().toString());
            status.setRollbackOnly();
            return committed;
        });
        assertNotNull(survivor);
        assertEquals("independent", sessions.authenticate(survivor.token()).orElseThrow().client());
        assertTrue(sessions.authenticate(outside.token()).isEmpty());
        sessions.revokeAll(owner);
    }
}
