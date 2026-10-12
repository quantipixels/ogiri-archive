// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri;

import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;
import static org.junit.jupiter.api.Assertions.*;

import com.sun.source.tree.ClassTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreeScanner;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.lang.model.element.Modifier;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;

class ModuleBoundariesTest {
    private static final String ROOT = "com.quantipixels.ogiri";
    private static final Set<String> API_PACKAGES =
            Set.of(ROOT, ROOT + ".account", ROOT + ".security", ROOT + ".mail", ROOT + ".spring");
    // Review changes alongside reports/slice4-20261012/api.md.
    private static final Set<String> API_TYPES =
            Set.of(
                    ROOT + ".IssuedSession",
                    ROOT + ".JdbcSessions",
                    ROOT + ".Session",
                    ROOT + ".SessionLimitException",
                    ROOT + ".SessionPolicy",
                    ROOT + ".SessionStoreException",
                    ROOT + ".Subject",
                    ROOT + ".account.AccountStore",
                    ROOT + ".account.OgiriAccount",
                    ROOT + ".account.OgiriAuthorities",
                    ROOT + ".security.OgiriAuthentication",
                    ROOT + ".security.OgiriConfigurer",
                    ROOT + ".security.OgiriRealms",
                    ROOT + ".security.OgiriRuntime",
                    ROOT + ".mail.OgiriMailer",
                    ROOT + ".spring.OgiriAutoConfiguration",
                    ROOT + ".spring.OgiriProperties",
                    ROOT + ".spring.OgiriRealmConfiguration");

    @Test
    void featureModulesHaveNoCycles() {
        slices().matching(ROOT + ".(*)..")
                .should()
                .beFreeOfCycles()
                .check(
                        new ClassFileImporter()
                                .withImportOption(new ImportOption.DoNotIncludeTests())
                                .importPackages(ROOT));
    }

    @Test
    void publicTopLevelTypesExactlyMatchReviewedApi() throws Exception {
        var actual = new HashSet<String>();
        for (String module : List.of("ogiri", "ogiri-spring-boot-autoconfigure")) {
            parse(
                    repository().resolve(module + "/src/main/java"),
                    unit -> {
                        String pkg = unit.getPackageName().toString();
                        for (var declaration : unit.getTypeDecls()) {
                            if (declaration instanceof ClassTree type
                                    && type.getModifiers().getFlags().contains(Modifier.PUBLIC)) {
                                if (API_PACKAGES.contains(pkg))
                                    actual.add(pkg + "." + type.getSimpleName());
                                else
                                    assertTrue(
                                            List.of(pkg.split("\\.")).contains("internal"),
                                            "Public type outside API/internal packages: "
                                                    + pkg
                                                    + "."
                                                    + type.getSimpleName());
                            }
                        }
                    });
        }
        assertEquals(API_TYPES, actual);
    }

    @Test
    void sampleMainReferencesOnlyApiPackages() throws Exception {
        parse(
                repository().resolve("examples/spring-app/src/main/java"),
                unit ->
                        new TreeScanner<Void, Void>() {
                            @Override
                            public Void visitMemberSelect(MemberSelectTree tree, Void unused) {
                                String reference = tree.toString();
                                if (reference.startsWith(ROOT + ".")) {
                                    String suffix = reference.substring(ROOT.length() + 1);
                                    String pkg = ROOT;
                                    for (String part : suffix.split("\\.")) {
                                        if (part.equals("*")
                                                || Character.isUpperCase(part.charAt(0))) break;
                                        pkg += "." + part;
                                    }
                                    assertTrue(
                                            API_PACKAGES.contains(pkg),
                                            "Non-API sample reference: " + reference);
                                }
                                return super.visitMemberSelect(tree, null);
                            }
                        }.scan(unit, null));
    }

    private static Path repository() {
        Path here = Path.of("").toAbsolutePath();
        return Files.isDirectory(here.resolve("ogiri")) ? here : here.getParent();
    }

    private static void parse(
            Path sources,
            java.util.function.Consumer<com.sun.source.tree.CompilationUnitTree> inspect)
            throws Exception {
        assertTrue(Files.isDirectory(sources), "Missing source root: " + sources);
        var compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull(compiler, "Boundary checks require a JDK");
        try (var files = Files.walk(sources);
                var manager = compiler.getStandardFileManager(null, null, null)) {
            var paths = files.filter(path -> path.toString().endsWith(".java")).toList();
            assertFalse(paths.isEmpty(), "No sources in " + sources);
            var diagnostics = new javax.tools.DiagnosticCollector<javax.tools.JavaFileObject>();
            var task =
                    (JavacTask)
                            compiler.getTask(
                                    null,
                                    manager,
                                    diagnostics,
                                    List.of("-proc:none"),
                                    null,
                                    manager.getJavaFileObjectsFromPaths(paths));
            task.parse().forEach(inspect);
            assertTrue(
                    diagnostics.getDiagnostics().stream()
                            .noneMatch(d -> d.getKind() == javax.tools.Diagnostic.Kind.ERROR),
                    diagnostics.getDiagnostics().toString());
        }
    }
}
