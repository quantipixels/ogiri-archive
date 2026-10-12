// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.spring;

import com.quantipixels.ogiri.SessionPolicy;
import com.quantipixels.ogiri.account.AccountStore;
import com.quantipixels.ogiri.account.OgiriAuthorities;
import com.quantipixels.ogiri.account.internal.AccountValidator;
import com.quantipixels.ogiri.account.internal.ActivationService;
import com.quantipixels.ogiri.account.internal.DevisePasswordEncoder;
import com.quantipixels.ogiri.account.internal.JdbcDeviseAccountStore;
import com.quantipixels.ogiri.account.internal.OgiriSettings;
import com.quantipixels.ogiri.account.internal.PasswordService;
import com.quantipixels.ogiri.account.internal.RegistrationService;
import com.quantipixels.ogiri.account.internal.SignInService;
import com.quantipixels.ogiri.internal.AuthTransactions;
import com.quantipixels.ogiri.internal.MailDispatcher;
import com.quantipixels.ogiri.internal.PublicLinks;
import com.quantipixels.ogiri.internal.SessionRepository;
import com.quantipixels.ogiri.security.OgiriRealms;
import com.quantipixels.ogiri.security.OgiriRuntime;
import com.quantipixels.ogiri.spring.internal.RedactedAuthenticationEvents;
import com.quantipixels.ogiri.web.internal.OgiriEndpoints;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.bind.PropertySourcesPlaceholdersResolver;
import org.springframework.boot.context.properties.source.ConfigurationPropertySource;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

@Configuration(proxyBeanMethods = false)
public class OgiriRealmConfiguration {
    record Mount(OgiriRuntime runtime, OgiriEndpoints endpoints, boolean enabled) {}

    record Mounts(List<Mount> values) {
        Mounts {
            values = List.copyOf(values);
        }
    }

    @Bean
    Mounts ogiriRealmMounts(
            OgiriProperties properties,
            Environment environment,
            AuthTransactions transactions,
            OgiriAuthorities authorities,
            AccountValidator validator,
            ObjectProvider<org.springframework.mail.javamail.JavaMailSender> senders,
            org.springframework.context.MessageSource messages,
            org.springframework.beans.factory.config.ConfigurableListableBeanFactory beans,
            org.springframework.context.ApplicationEventPublisher applicationEvents,
            ApplicationContext context,
            org.springframework.security.authentication.AuthenticationEventPublisher events) {
        var mounts = new ArrayList<Mount>();
        var tables = new java.util.HashSet<String>();
        tables.add(properties.account().table().toLowerCase(java.util.Locale.ROOT));
        for (String name : properties.realms().keySet().stream().sorted().toList()) {
            if (!name.matches("[a-z][a-z0-9-]*"))
                throw new IllegalArgumentException(
                        "Ogiri realm keys must be canonical lowercase names");
            var sources = new ArrayList<ConfigurationPropertySource>();
            sources.add(new MapConfigurationPropertySource(java.util.Map.of("realm", name)));
            ConfigurationPropertySources.get(environment)
                    .forEach(source -> sources.add(source.withPrefix("ogiri.realms." + name)));
            ConfigurationPropertySources.get(environment)
                    .forEach(source -> sources.add(source.withPrefix("ogiri")));
            var realm =
                    new Binder(sources, new PropertySourcesPlaceholdersResolver(environment))
                            .bindOrCreate("", OgiriProperties.class);
            var settings = realm.settings();
            OgiriAutoConfiguration.validateFeatures(realm);
            AccountStore accounts =
                    collaborator(
                            context,
                            beans,
                            name,
                            "OgiriAccountStore",
                            AccountStore.class,
                            "ogiriAccountStore",
                            () -> null);
            if (accounts == null) {
                if (!tables.add(realm.account().table().toLowerCase(java.util.Locale.ROOT))) {
                    throw new IllegalArgumentException(
                            "Ogiri realms must use distinct account tables; configure ogiri.realms."
                                    + name
                                    + ".account.table or an explicit "
                                    + name
                                    + "OgiriAccountStore bean");
                }
                accounts =
                        new JdbcDeviseAccountStore(
                                transactions,
                                realm.account().table(),
                                authorities,
                                realm.account().columns());
            }
            var encoder =
                    collaborator(
                            context,
                            beans,
                            name,
                            "OgiriPasswordEncoder",
                            com.quantipixels.ogiri.account.internal.OgiriPasswords.class,
                            "ogiriPasswordEncoder",
                            () ->
                                    new com.quantipixels.ogiri.account.internal.OgiriPasswords(
                                            new DevisePasswordEncoder(realm.bcryptCost())));
            var accountValidator =
                    collaborator(
                            context,
                            beans,
                            name,
                            "OgiriAccountValidator",
                            AccountValidator.class,
                            "ogiriAccountValidator",
                            () -> validator);
            var mailer =
                    collaborator(
                            context,
                            beans,
                            name,
                            "OgiriMailer",
                            com.quantipixels.ogiri.mail.OgiriMailer.class,
                            "ogiriMailer",
                            () ->
                                    new com.quantipixels.ogiri.internal.JavaMailOgiriMailer(
                                            senders.getObject(), messages, realm.mailFrom()));
            var sessions =
                    new SessionRepository(
                            transactions,
                            new SessionPolicy(
                                    settings.tokenLifespan(), settings.maxNumberOfDevices()));
            var manager =
                    new org.springframework.security.authentication.ProviderManager(
                            new com.quantipixels.ogiri.security.internal
                                    .OgiriTokenAuthenticationProvider(
                                    accounts, transactions, sessions, settings));
            manager.setAuthenticationEventPublisher(
                    new RedactedAuthenticationEvents(events, settings.realm()));
            var graph =
                    RealmFactory.create(
                            settings,
                            accounts,
                            transactions,
                            sessions,
                            encoder.encoder(),
                            accountValidator,
                            new MailDispatcher(applicationEvents, mailer),
                            OgiriAutoConfiguration.links(realm, environment),
                            events,
                            request -> manager);
            mounts.add(new Mount(graph.runtime(), graph.endpoints(), realm.endpoints().enabled()));
        }
        return new Mounts(mounts);
    }

    private static <T> T collaborator(
            ApplicationContext context,
            org.springframework.beans.factory.config.ConfigurableListableBeanFactory beans,
            String realm,
            String suffix,
            Class<T> type,
            String defaultBean,
            java.util.function.Supplier<T> fallback) {
        String name = realm + suffix;
        if (context.containsBean(name)) return context.getBean(name, type);
        // Let Spring choose the shared candidate (including @Primary and defaultCandidate=false).
        var shared = context.getBeanProvider(type).getIfAvailable();
        boolean generatedDefault =
                shared != null
                        && context.containsBean(defaultBean)
                        && shared == context.getBean(defaultBean)
                        && beans.containsBeanDefinition(defaultBean)
                        && OgiriAutoConfiguration.class
                                .getName()
                                .equals(beans.getBeanDefinition(defaultBean).getFactoryBeanName());
        if (shared != null && !generatedDefault) return shared;
        return fallback.get();
    }

    @Bean
    OgiriRealms ogiriRealms(OgiriRuntime runtime, Mounts mounts, OgiriProperties properties) {
        var disabled = new java.util.HashSet<String>();
        if (!properties.endpoints().enabled()) disabled.add(runtime.settings().realm());
        mounts.values().stream()
                .filter(mount -> !mount.enabled())
                .forEach(mount -> disabled.add(mount.runtime().settings().realm()));
        return new OgiriRealms(
                runtime, mounts.values().stream().map(Mount::runtime).toList(), disabled);
    }

    @Bean
    SmartInitializingSingleton ogiriRealmMappings(
            Mounts mounts,
            @org.springframework.beans.factory.annotation.Qualifier("requestMappingHandlerMapping")
                    ObjectProvider<RequestMappingHandlerMapping> mappings) {
        return () -> {
            var mapping = mappings.getIfAvailable();
            if (mapping == null || mounts.values().isEmpty()) return;
            mounts.values().stream()
                    .filter(Mount::enabled)
                    .forEach(mount -> registerMount(mapping, mount));
        };
    }

    private static void registerMount(RequestMappingHandlerMapping mapping, Mount mount) {
        var handlers =
                org.springframework.core.MethodIntrospector.selectMethods(
                        OgiriEndpoints.class,
                        (org.springframework.core.MethodIntrospector.MetadataLookup<
                                        org.springframework.web.bind.annotation.RequestMapping>)
                                method ->
                                        org.springframework.core.annotation.AnnotatedElementUtils
                                                .findMergedAnnotation(
                                                        method,
                                                        org.springframework.web.bind.annotation
                                                                .RequestMapping.class));
        var pathsInUse =
                mapping.getHandlerMethods().keySet().stream()
                        .flatMap(info -> info.getPatternValues().stream())
                        .collect(java.util.stream.Collectors.toSet());
        for (var route : handlers.values()) {
            for (var path : route.path()) {
                String mounted = mount.runtime().settings().basePath() + path;
                if (pathsInUse.contains(mounted)) {
                    throw new IllegalArgumentException(
                            "Duplicate Ogiri realm endpoint path: " + mounted);
                }
            }
        }
        for (var handler : handlers.entrySet()) {
            var method = handler.getKey();
            var route = handler.getValue();
            String[] paths =
                    java.util.Arrays.stream(route.path())
                            .map(path -> mount.runtime().settings().basePath() + path)
                            .toArray(String[]::new);
            var info =
                    org.springframework.web.servlet.mvc.method.RequestMappingInfo.paths(paths)
                            .methods(route.method())
                            .consumes(route.consumes())
                            .produces(route.produces())
                            .params(route.params())
                            .headers(route.headers())
                            .options(mapping.getBuilderConfiguration())
                            .build();
            mapping.registerMapping(info, mount.endpoints(), method);
        }
    }

    /** The same workflow graph serves the root mount and every additional realm. */
    static final class RealmFactory {
        private RealmFactory() {}

        record Realm(
                OgiriRuntime runtime,
                OgiriEndpoints endpoints,
                ActivationService activation,
                RegistrationService registration,
                PasswordService passwords) {}

        static Realm create(
                OgiriSettings settings,
                AccountStore accounts,
                AuthTransactions transactions,
                SessionRepository sessions,
                DevisePasswordEncoder encoder,
                AccountValidator validator,
                MailDispatcher mail,
                PublicLinks links,
                AuthenticationEventPublisher events,
                AuthenticationManagerResolver<HttpServletRequest> managers) {
            var activation =
                    new ActivationService(accounts, transactions, sessions, settings, mail, links);
            var signIn =
                    new SignInService(
                            accounts, transactions, sessions, settings, encoder, activation);
            signIn.setAuthenticationEventPublisher(events);
            var registration =
                    new RegistrationService(
                            accounts,
                            transactions,
                            sessions,
                            settings,
                            encoder,
                            signIn,
                            validator,
                            activation);
            var passwords =
                    new PasswordService(
                            accounts,
                            transactions,
                            sessions,
                            settings,
                            encoder,
                            signIn,
                            validator,
                            mail,
                            links);
            var runtime =
                    new OgiriRuntime(settings, transactions, sessions, accounts, signIn, managers);
            return new Realm(
                    runtime,
                    new OgiriEndpoints(runtime, registration, passwords, activation),
                    activation,
                    registration,
                    passwords);
        }
    }
}
