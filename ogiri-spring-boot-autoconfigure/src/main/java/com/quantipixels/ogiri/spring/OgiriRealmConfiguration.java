// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.spring;

import com.quantipixels.ogiri.SessionPolicy;
import com.quantipixels.ogiri.account.AccountStore;
import com.quantipixels.ogiri.account.AccountValidator;
import com.quantipixels.ogiri.account.ActivationService;
import com.quantipixels.ogiri.account.DevisePasswordEncoder;
import com.quantipixels.ogiri.account.JdbcDeviseAccountStore;
import com.quantipixels.ogiri.account.OgiriAuthorities;
import com.quantipixels.ogiri.account.PasswordService;
import com.quantipixels.ogiri.account.RegistrationService;
import com.quantipixels.ogiri.account.SignInService;
import com.quantipixels.ogiri.internal.AuthTransactions;
import com.quantipixels.ogiri.internal.MailDispatcher;
import com.quantipixels.ogiri.internal.SessionRepository;
import com.quantipixels.ogiri.security.OgiriRealms;
import com.quantipixels.ogiri.security.OgiriRuntime;
import com.quantipixels.ogiri.web.internal.OgiriEndpoints;
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
            MailDispatcher mail,
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
            String storeName = name + "OgiriAccountStore";
            if (!context.containsBean(storeName)
                    && !tables.add(realm.account().table().toLowerCase(java.util.Locale.ROOT))) {
                throw new IllegalArgumentException(
                        "Ogiri realms must use distinct account tables; configure ogiri.realms."
                                + name
                                + ".account.table or an explicit "
                                + storeName
                                + " bean");
            }
            AccountStore accounts =
                    context.containsBean(storeName)
                            ? context.getBean(storeName, AccountStore.class)
                            : new JdbcDeviseAccountStore(
                                    transactions,
                                    realm.account().table(),
                                    authorities,
                                    realm.account().columns());
            var sessions =
                    new SessionRepository(
                            transactions,
                            new SessionPolicy(
                                    settings.tokenLifespan(), settings.maxNumberOfDevices()));
            var links = OgiriAutoConfiguration.links(realm, environment);
            var activation =
                    new ActivationService(accounts, transactions, sessions, settings, mail, links);
            var encoder = new DevisePasswordEncoder(realm.bcryptCost());
            var signin =
                    new SignInService(
                            accounts, transactions, sessions, settings, encoder, activation);
            signin.setAuthenticationEventPublisher(events);
            var registration =
                    new RegistrationService(
                            accounts,
                            transactions,
                            sessions,
                            settings,
                            encoder,
                            signin,
                            validator,
                            activation);
            var passwords =
                    new PasswordService(
                            accounts,
                            transactions,
                            sessions,
                            settings,
                            encoder,
                            signin,
                            validator,
                            mail,
                            links);
            var manager =
                    new org.springframework.security.authentication.ProviderManager(
                            new com.quantipixels.ogiri.security.OgiriTokenAuthenticationProvider(
                                    accounts, transactions, sessions, settings));
            manager.setAuthenticationEventPublisher(new RedactedAuthenticationEvents(events));
            var runtime =
                    new OgiriRuntime(
                            settings, transactions, sessions, accounts, signin, request -> manager);
            mounts.add(
                    new Mount(
                            runtime,
                            new OgiriEndpoints(runtime, registration, passwords, activation),
                            realm.endpoints().enabled()));
        }
        return new Mounts(mounts);
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
        for (var method : OgiriEndpoints.class.getMethods()) {
            var route =
                    org.springframework.core.annotation.AnnotatedElementUtils.findMergedAnnotation(
                            method, org.springframework.web.bind.annotation.RequestMapping.class);
            if (route == null) continue;
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
}
