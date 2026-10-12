// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.spring;

import com.quantipixels.ogiri.SessionPolicy;
import com.quantipixels.ogiri.account.AccountStore;
import com.quantipixels.ogiri.account.OgiriAuthorities;
import com.quantipixels.ogiri.account.internal.DevisePasswordEncoder;
import com.quantipixels.ogiri.account.internal.JdbcDeviseAccountStore;
import com.quantipixels.ogiri.account.internal.OgiriSettings;
import com.quantipixels.ogiri.account.internal.SignInService;
import com.quantipixels.ogiri.internal.AuthTransactions;
import com.quantipixels.ogiri.internal.SessionRepository;
import com.quantipixels.ogiri.security.OgiriConfigurer;
import com.quantipixels.ogiri.security.OgiriRuntime;
import com.quantipixels.ogiri.spring.internal.OgiriSessionCleanup;
import com.quantipixels.ogiri.spring.internal.RedactedAuthenticationEvents;
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
    com.quantipixels.ogiri.account.internal.OgiriPasswords ogiriPasswordEncoder(
            OgiriProperties properties) {
        return new com.quantipixels.ogiri.account.internal.OgiriPasswords(
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
    SignInService ogiriSignIn(OgiriRealmConfiguration.RealmFactory.Realm realm) {
        return realm.runtime().signIn();
    }

    @Bean
    @ConditionalOnMissingBean(jakarta.validation.Validator.class)
    org.springframework.validation.beanvalidation.LocalValidatorFactoryBean ogiriBeanValidation() {
        return new org.springframework.validation.beanvalidation.LocalValidatorFactoryBean();
    }

    @Bean
    @ConditionalOnMissingBean
    com.quantipixels.ogiri.account.internal.AccountValidator ogiriAccountValidator(
            jakarta.validation.Validator validator) {
        return new com.quantipixels.ogiri.account.internal.AccountValidator(validator);
    }

    @Bean
    @ConditionalOnMissingBean
    com.quantipixels.ogiri.account.internal.RegistrationService ogiriRegistration(
            OgiriRealmConfiguration.RealmFactory.Realm realm) {
        return realm.registration();
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
    com.quantipixels.ogiri.account.internal.ActivationService ogiriActivation(
            OgiriRealmConfiguration.RealmFactory.Realm realm) {
        return realm.activation();
    }

    @Bean
    @ConditionalOnMissingBean
    com.quantipixels.ogiri.account.internal.PasswordService ogiriPasswordService(
            OgiriRealmConfiguration.RealmFactory.Realm realm) {
        return realm.passwords();
    }

    @Bean
    @ConditionalOnMissingBean(name = "ogiriAuthenticationManagers")
    @org.springframework.beans.factory.annotation.Qualifier("ogiriAuthenticationManagers")
    org.springframework.security.authentication.AuthenticationManagerResolver<
                    jakarta.servlet.http.HttpServletRequest>
            ogiriAuthenticationManagers(
                    ObjectProvider<
                                    com.quantipixels.ogiri.security.internal
                                            .OgiriTokenAuthenticationProvider>
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
                                new com.quantipixels.ogiri.security.internal
                                        .OgiriTokenAuthenticationProvider(
                                        accounts, transactions, sessions, settings));
        var manager = new org.springframework.security.authentication.ProviderManager(provider);
        manager.setAuthenticationEventPublisher(
                new RedactedAuthenticationEvents(events, settings.realm()));
        return request -> manager;
    }

    @Bean
    OgiriRealmConfiguration.RealmFactory.Realm ogiriDefaultRealm(
            OgiriSettings settings,
            AuthTransactions transactions,
            SessionRepository sessions,
            AccountStore accounts,
            com.quantipixels.ogiri.account.internal.OgiriPasswords encoder,
            com.quantipixels.ogiri.account.internal.AccountValidator validator,
            com.quantipixels.ogiri.internal.MailDispatcher mail,
            com.quantipixels.ogiri.internal.PublicLinks links,
            org.springframework.security.authentication.AuthenticationEventPublisher events,
            @org.springframework.beans.factory.annotation.Qualifier("ogiriAuthenticationManagers")
                    org.springframework.security.authentication.AuthenticationManagerResolver<
                                    jakarta.servlet.http.HttpServletRequest>
                            managers) {
        return OgiriRealmConfiguration.RealmFactory.create(
                settings,
                accounts,
                transactions,
                sessions,
                encoder.encoder(),
                validator,
                mail,
                links,
                events,
                managers);
    }

    @Bean
    @ConditionalOnMissingBean
    OgiriRuntime ogiriRuntime(OgiriRealmConfiguration.RealmFactory.Realm realm) {
        return realm.runtime();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
            prefix = "ogiri.endpoints",
            name = "enabled",
            havingValue = "true",
            matchIfMissing = true)
    OgiriEndpoints ogiriEndpoints(OgiriRealmConfiguration.RealmFactory.Realm realm) {
        return realm.endpoints();
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    SecurityFilterChain ogiriSecurityFilterChain(
            HttpSecurity http,
            OgiriRuntime runtime,
            com.quantipixels.ogiri.security.OgiriRealms realms,
            OgiriProperties properties)
            throws Exception {
        // These defaults belong only to the fallback chain owned by Ogiri.
        http.sessionManagement(
                        config ->
                                config.sessionCreationPolicy(
                                        org.springframework.security.config.http
                                                .SessionCreationPolicy.STATELESS))
                .requestCache(
                        org.springframework.security.config.annotation.web.configurers
                                        .AbstractHttpConfigurer
                                ::disable)
                // Spring's default CsrfFilter is replaced, not dropped: OgiriConfigurer (below)
                // installs
                // OgiriCsrfFilter, which requires a token on every unsafe cookie-authenticated
                // request.
                .csrf(
                        org.springframework.security.config.annotation.web.configurers
                                        .AbstractHttpConfigurer
                                ::disable)
                .exceptionHandling(
                        config ->
                                config.authenticationEntryPoint(
                                                (request, response, failure) ->
                                                        com.quantipixels.ogiri.security.internal
                                                                .DtaErrors.unauthorized(
                                                                request,
                                                                response,
                                                                realms.resolve(request)
                                                                        .settings()
                                                                        .basePath()))
                                        .accessDeniedHandler(
                                                (request, response, failure) ->
                                                        com.quantipixels.ogiri.security.internal
                                                                .DtaErrors.forbidden(response)));
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
