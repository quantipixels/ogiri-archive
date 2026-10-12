// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.spring;

import com.quantipixels.ogiri.SessionPolicy;
import com.quantipixels.ogiri.account.AccountStore;
import com.quantipixels.ogiri.account.DevisePasswordEncoder;
import com.quantipixels.ogiri.account.JdbcDeviseAccountStore;
import com.quantipixels.ogiri.account.OgiriAuthorities;
import com.quantipixels.ogiri.account.OgiriSettings;
import com.quantipixels.ogiri.account.SignInService;
import com.quantipixels.ogiri.internal.AuthTransactions;
import com.quantipixels.ogiri.internal.SessionRepository;
import com.quantipixels.ogiri.security.OgiriConfigurer;
import com.quantipixels.ogiri.security.OgiriRuntime;
import com.quantipixels.ogiri.web.internal.OgiriEndpoints;
import javax.sql.DataSource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.transaction.PlatformTransactionManager;

@AutoConfiguration(
        afterName = {
            "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
            "org.springframework.boot.jdbc.autoconfigure.DataSourceTransactionManagerAutoConfiguration",
            "org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration",
            "org.springframework.boot.mail.autoconfigure.MailSenderAutoConfiguration"
        },
        beforeName = {
            "org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration",
            "org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration"
        })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(DataSource.class)
@ConditionalOnProperty(
        prefix = "ogiri",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
@EnableConfigurationProperties(OgiriProperties.class)
@org.springframework.context.annotation.Import(OgiriRealmConfiguration.class)
@EnableWebSecurity
@org.springframework.transaction.annotation.EnableTransactionManagement
public final class OgiriAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean
    OgiriSettings ogiriSettings(OgiriProperties properties) {
        validateFeatures(properties);
        return properties.settings();
    }

    static void validateFeatures(OgiriProperties properties) {
        var cleanup = properties.cleanup();
        if (cleanup.batchSize() < 1 || cleanup.batchSize() > 10000)
            throw new IllegalArgumentException(
                    "Ogiri cleanup batch size must be between 1 and 10000");
        if (cleanup.interval() != null && cleanup.interval().toMillis() < 1)
            throw new IllegalArgumentException("Ogiri cleanup interval must be positive");
    }

    @Bean
    @ConditionalOnMissingBean(
            org.springframework.security.authentication.AuthenticationEventPublisher.class)
    org.springframework.security.authentication.AuthenticationEventPublisher
            ogiriAuthenticationEvents(
                    org.springframework.context.ApplicationEventPublisher events) {
        return new org.springframework.security.authentication.DefaultAuthenticationEventPublisher(
                events);
    }

    @Bean
    @ConditionalOnProperty(prefix = "ogiri.cleanup", name = "interval")
    OgiriSessionCleanup ogiriCleanupScheduler(
            SessionRepository sessions, OgiriProperties properties) {
        validateFeatures(properties);
        return new OgiriSessionCleanup(sessions, properties.cleanup());
    }

    @Bean
    @ConditionalOnMissingBean
    AuthTransactions ogiriTransactions(
            DataSource source, ObjectProvider<PlatformTransactionManager> managers) {
        var available = managers.orderedStream().toList();
        if (available.size() > 1) {
            throw new IllegalStateException(
                    "Multiple transaction managers found; provide an AuthTransactions bean for Ogiri's DataSource");
        }
        return available.isEmpty()
                ? new AuthTransactions(source)
                : new AuthTransactions(source, available.get(0));
    }

    @Bean
    @ConditionalOnMissingBean
    SessionRepository ogiriSessions(AuthTransactions transactions, OgiriSettings settings) {
        return new SessionRepository(
                transactions,
                new SessionPolicy(settings.tokenLifespan(), settings.maxNumberOfDevices()));
    }

    @Bean
    @ConditionalOnMissingBean
    com.quantipixels.ogiri.account.OgiriPasswords ogiriPasswordEncoder(OgiriProperties properties) {
        return new com.quantipixels.ogiri.account.OgiriPasswords(
                new DevisePasswordEncoder(properties.bcryptCost()));
    }

    @Bean
    @ConditionalOnMissingBean
    OgiriAuthorities ogiriAuthorities() {
        return columns -> java.util.List.of();
    }

    @Bean
    @ConditionalOnMissingBean(AccountStore.class)
    AccountStore ogiriAccountStore(
            AuthTransactions transactions,
            OgiriProperties properties,
            OgiriAuthorities authorities) {
        return new JdbcDeviseAccountStore(
                transactions,
                properties.account().table(),
                authorities,
                properties.account().columns());
    }

    @Bean
    @ConditionalOnMissingBean
    SignInService ogiriSignIn(
            AccountStore accounts,
            AuthTransactions transactions,
            SessionRepository sessions,
            OgiriSettings settings,
            com.quantipixels.ogiri.account.OgiriPasswords passwords,
            com.quantipixels.ogiri.account.ActivationService activation,
            org.springframework.security.authentication.AuthenticationEventPublisher events) {
        var signIn =
                new SignInService(
                        accounts,
                        transactions,
                        sessions,
                        settings,
                        passwords.encoder(),
                        activation);
        signIn.setAuthenticationEventPublisher(events);
        return signIn;
    }

    @Bean
    @ConditionalOnMissingBean(jakarta.validation.Validator.class)
    org.springframework.validation.beanvalidation.LocalValidatorFactoryBean ogiriBeanValidation() {
        return new org.springframework.validation.beanvalidation.LocalValidatorFactoryBean();
    }

    @Bean
    @ConditionalOnMissingBean
    com.quantipixels.ogiri.account.AccountValidator ogiriAccountValidator(
            jakarta.validation.Validator validator) {
        return new com.quantipixels.ogiri.account.AccountValidator(validator);
    }

    @Bean
    @ConditionalOnMissingBean
    com.quantipixels.ogiri.account.RegistrationService ogiriRegistration(
            AccountStore accounts,
            AuthTransactions transactions,
            SessionRepository sessions,
            OgiriSettings settings,
            com.quantipixels.ogiri.account.OgiriPasswords passwords,
            SignInService signIn,
            com.quantipixels.ogiri.account.AccountValidator validator,
            com.quantipixels.ogiri.account.ActivationService activation) {
        return new com.quantipixels.ogiri.account.RegistrationService(
                accounts,
                transactions,
                sessions,
                settings,
                passwords.encoder(),
                signIn,
                validator,
                activation);
    }

    @Bean
    @ConditionalOnMissingBean
    com.quantipixels.ogiri.internal.PublicLinks ogiriLinks(
            OgiriProperties properties, org.springframework.core.env.Environment environment) {
        return links(properties, environment);
    }

    static com.quantipixels.ogiri.internal.PublicLinks links(
            OgiriProperties properties, org.springframework.core.env.Environment environment) {
        String url =
                properties.publicBaseUrl().isBlank()
                        ? environment.getProperty("spring.application.url", "")
                        : properties.publicBaseUrl();
        String context = environment.getProperty("server.servlet.context-path", "");
        String servlet = environment.getProperty("spring.mvc.servlet.path", "");
        return new com.quantipixels.ogiri.internal.PublicLinks(
                url,
                (context.equals("/") ? "" : context)
                        + (servlet.equals("/") ? "" : servlet)
                        + properties.basePath(),
                properties.redirectAllowlist());
    }

    @Bean
    @ConditionalOnMissingBean(com.quantipixels.ogiri.mail.OgiriMailer.class)
    com.quantipixels.ogiri.mail.OgiriMailer ogiriMailer(
            ObjectProvider<org.springframework.mail.javamail.JavaMailSender> senders,
            org.springframework.context.MessageSource messages,
            OgiriProperties properties) {
        var sender = senders.getIfAvailable();
        if (sender == null)
            throw new IllegalStateException(
                    "Ogiri password recovery requires JavaMailSender or OgiriMailer");
        return new com.quantipixels.ogiri.internal.JavaMailOgiriMailer(
                sender, messages, properties.mailFrom());
    }

    @Bean
    com.quantipixels.ogiri.internal.MailDispatcher ogiriMailDispatcher(
            org.springframework.context.ApplicationEventPublisher events,
            com.quantipixels.ogiri.mail.OgiriMailer mailer) {
        return new com.quantipixels.ogiri.internal.MailDispatcher(events, mailer);
    }

    @Bean
    @ConditionalOnMissingBean
    com.quantipixels.ogiri.account.ActivationService ogiriActivation(
            AccountStore accounts,
            AuthTransactions transactions,
            SessionRepository sessions,
            OgiriSettings settings,
            com.quantipixels.ogiri.internal.MailDispatcher mail,
            com.quantipixels.ogiri.internal.PublicLinks links) {
        return new com.quantipixels.ogiri.account.ActivationService(
                accounts, transactions, sessions, settings, mail, links);
    }

    @Bean
    @ConditionalOnMissingBean
    com.quantipixels.ogiri.account.PasswordService ogiriPasswordService(
            AccountStore accounts,
            AuthTransactions transactions,
            SessionRepository sessions,
            OgiriSettings settings,
            com.quantipixels.ogiri.account.OgiriPasswords passwords,
            SignInService signIn,
            com.quantipixels.ogiri.account.AccountValidator validator,
            com.quantipixels.ogiri.internal.MailDispatcher mail,
            com.quantipixels.ogiri.internal.PublicLinks links) {
        return new com.quantipixels.ogiri.account.PasswordService(
                accounts,
                transactions,
                sessions,
                settings,
                passwords.encoder(),
                signIn,
                validator,
                mail,
                links);
    }

    @Bean
    @ConditionalOnMissingBean(name = "ogiriAuthenticationManagers")
    @org.springframework.beans.factory.annotation.Qualifier("ogiriAuthenticationManagers")
    org.springframework.security.authentication.AuthenticationManagerResolver<
                    jakarta.servlet.http.HttpServletRequest>
            ogiriAuthenticationManagers(
                    ObjectProvider<com.quantipixels.ogiri.security.OgiriTokenAuthenticationProvider>
                            providers,
                    AccountStore accounts,
                    AuthTransactions transactions,
                    SessionRepository sessions,
                    OgiriSettings settings,
                    org.springframework.security.authentication.AuthenticationEventPublisher
                            events) {
        var provider =
                providers.getIfAvailable(
                        () ->
                                new com.quantipixels.ogiri.security
                                        .OgiriTokenAuthenticationProvider(
                                        accounts, transactions, sessions, settings));
        var manager = new org.springframework.security.authentication.ProviderManager(provider);
        manager.setAuthenticationEventPublisher(
                new RedactedAuthenticationEvents(events, settings.realm()));
        return request -> manager;
    }

    @Bean
    @ConditionalOnMissingBean
    OgiriRuntime ogiriRuntime(
            OgiriSettings settings,
            AuthTransactions transactions,
            SessionRepository sessions,
            AccountStore accounts,
            SignInService signIn,
            @org.springframework.beans.factory.annotation.Qualifier("ogiriAuthenticationManagers")
                    org.springframework.security.authentication.AuthenticationManagerResolver<
                                    jakarta.servlet.http.HttpServletRequest>
                            managers) {
        return new OgiriRuntime(settings, transactions, sessions, accounts, signIn, managers);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
            prefix = "ogiri.endpoints",
            name = "enabled",
            havingValue = "true",
            matchIfMissing = true)
    OgiriEndpoints ogiriEndpoints(
            OgiriRuntime runtime,
            com.quantipixels.ogiri.account.RegistrationService registration,
            com.quantipixels.ogiri.account.PasswordService passwords,
            com.quantipixels.ogiri.account.ActivationService activation) {
        return new OgiriEndpoints(runtime, registration, passwords, activation);
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    SecurityFilterChain ogiriSecurityFilterChain(
            HttpSecurity http,
            OgiriRuntime runtime,
            com.quantipixels.ogiri.security.OgiriRealms realms,
            OgiriProperties properties)
            throws Exception {
        http.with(OgiriConfigurer.ogiri(realms), config -> {});
        return http.authorizeHttpRequests(
                        routes ->
                                routes.dispatcherTypeMatchers(jakarta.servlet.DispatcherType.ERROR)
                                        .permitAll()
                                        .requestMatchers(
                                                request ->
                                                        realms.endpointsEnabled(request)
                                                                && (OgiriConfigurer.publicWorkflow(
                                                                                request,
                                                                                realms.resolve(
                                                                                                request)
                                                                                        .settings()
                                                                                        .basePath())
                                                                        || OgiriConfigurer
                                                                                .tokenResetWorkflow(
                                                                                        request,
                                                                                        realms.resolve(
                                                                                                        request)
                                                                                                .settings())))
                                        .permitAll()
                                        .anyRequest()
                                        .authenticated())
                .build();
    }
}
