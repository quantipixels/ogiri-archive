// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import com.quantipixels.ogiri.account.OgiriAccount;
import com.quantipixels.ogiri.account.OgiriAuthorities;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@EnableMethodSecurity
@RestController
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    OgiriAuthorities roles() {
        return attributes ->
                List.of(
                        new SimpleGrantedAuthority(
                                "ROLE_"
                                        + String.valueOf(attributes.getOrDefault("role", "user"))
                                                .toUpperCase(Locale.ROOT)));
    }

    @GetMapping("/me")
    public Map<String, String> me(@AuthenticationPrincipal OgiriAccount account) {
        return Map.of("uid", account.uid());
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> admin(@AuthenticationPrincipal OgiriAccount account) {
        return Map.of("uid", account.uid());
    }
}
