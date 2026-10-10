// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Quanti Pixels
package com.quantipixels.ogiri.spring;


import com.quantipixels.ogiri.JdbcSessions;
import com.quantipixels.ogiri.SessionPolicy;
import com.quantipixels.ogiri.Subject;
import javax.sql.DataSource;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/** Boot owns discovery, configuration binding, pooling and native Security integration. */
@AutoConfiguration(
        afterName = {"org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
                "org.springframework.boot.jdbc.autoconfigure.DataSourceTransactionManagerAutoConfiguration",
                "org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration"},
        before = {org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration.class,
                org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerAutoConfiguration.class,
                org.springframework.boot.security.oauth2.server.resource.autoconfigure.web.OAuth2ResourceServerWebSecurityAutoConfiguration.class})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "ogiri", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(OgiriProperties.class)
@EnableWebSecurity
public final class OgiriAutoConfiguration {
    @Bean @ConditionalOnMissingBean
    SessionPolicy ogiriPolicy(OgiriProperties properties) {
        return new SessionPolicy(properties.lifetime(), properties.maximumSessions());
    }

    @Bean @ConditionalOnMissingBean
    JdbcSessions ogiriSessions(org.springframework.beans.factory.ObjectProvider<DataSource> sources, SessionPolicy policy,
            org.springframework.beans.factory.ObjectProvider<org.springframework.transaction.PlatformTransactionManager> managers) {
        var source = sources.getIfAvailable();
        if (source == null) throw new IllegalStateException("ogiri.enabled requires an application DataSource");
        var available = managers.orderedStream().toList();
        if (available.size() > 1)
            throw new IllegalStateException("Multiple transaction managers found; provide a JdbcSessions bean using the manager for Ogiri's DataSource");
        var manager = available.isEmpty() ? null : available.get(0);
        if (manager instanceof org.springframework.jdbc.datasource.DataSourceTransactionManager jdbcManager
                && jdbcManager.getDataSource() != source)
            throw new IllegalStateException("Ogiri's transaction manager must manage the configured DataSource");
        if (manager == null) {
            var jdbcManager = new org.springframework.jdbc.support.JdbcTransactionManager(source);
            jdbcManager.setRollbackOnCommitFailure(true);
            manager = jdbcManager;
        }
        return new JdbcSessions(source, policy, manager);
    }

    /** Spring's delegating encoder; unprefixed hashes such as Devise's {@code $2a$...} are verified as bcrypt. */
    @Bean @ConditionalOnMissingBean
    PasswordEncoder ogiriPasswordEncoder() {
        var encoder = (DelegatingPasswordEncoder) PasswordEncoderFactories.createDelegatingPasswordEncoder();
        encoder.setDefaultPasswordEncoderForMatches(new BCryptPasswordEncoder());
        return encoder;
    }

    @Bean @ConditionalOnMissingBean @ConditionalOnBean(UserDetailsService.class)
    OgiriAccounts ogiriAccounts(UserDetailsService users, OgiriProperties properties) {
        return new OgiriAccounts() {
            public Subject subject(Authentication authentication) {
                return new Subject(properties.realm(), "", authentication.getName());
            }
            public UserDetails load(Subject subject) {
                if (!subject.realm().equals(properties.realm()) || !subject.tenantId().isEmpty())
                    throw new UsernameNotFoundException("Account outside default identity namespace");
                return users.loadUserByUsername(subject.subjectId());
            }
        };
    }

    @Bean @ConditionalOnMissingBean
    OgiriOpaqueTokenIntrospector ogiriIntrospector(JdbcSessions sessions, OgiriAccounts accounts) {
        return new OgiriOpaqueTokenIntrospector(sessions, accounts::load);
    }

    @Bean @ConditionalOnMissingBean
    OgiriSecurity ogiriSecurity(OgiriOpaqueTokenIntrospector introspector, OgiriProperties properties,
            org.springframework.core.env.Environment environment) {
        return new OgiriSecurity(introspector, properties, environment.getProperty("spring.mvc.servlet.path", ""));
    }

    @Bean @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "ogiri", name = "endpoints-enabled", havingValue = "true", matchIfMissing = true)
    OgiriEndpoints ogiriEndpoints(JdbcSessions sessions, OgiriAccounts accounts,
            org.springframework.beans.factory.ObjectProvider<AuthenticationManager> managers,
            AuthenticationConfiguration configuration) throws Exception {
        var manager = managers.getIfAvailable();
        if (manager == null) manager = configuration.getAuthenticationManager();
        if (manager == null) throw new IllegalStateException("Provide a UserDetailsService, AuthenticationProvider or AuthenticationManager");
        return new OgiriEndpoints(sessions, accounts, manager);
    }

    @Bean @ConditionalOnMissingBean(SecurityFilterChain.class)
    SecurityFilterChain ogiriSecurityFilterChain(HttpSecurity http, OgiriSecurity security) throws Exception {
        return security.defaults(http);
    }
}
