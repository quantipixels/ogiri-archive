// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import java.security.Principal;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.userdetails.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@EnableMethodSecurity
@RestController
public class Application {
    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    /** The existing DeviseTokenAuth users table is the account directory; its bcrypt hashes verify unchanged. */
    @Bean
    UserDetailsService accounts(JdbcClient db) {
        return email -> db.sql("SELECT email, encrypted_password, role, locked_at IS NOT NULL AS locked FROM users WHERE email = ?")
                .param(email)
                .query((row, n) -> User.withUsername(row.getString("email"))
                        .password(row.getString("encrypted_password"))
                        .roles(row.getString("role").toUpperCase(java.util.Locale.ROOT))
                        .accountLocked(row.getBoolean("locked"))
                        .build())
                .optional()
                .orElseThrow(() -> new UsernameNotFoundException("Unknown account"));
    }

    @GetMapping(value = "/me", produces = "text/plain") String me(Principal principal) { return principal.getName(); }
    @GetMapping(value = "/admin", produces = "text/plain") @PreAuthorize("hasRole('ADMIN')") String admin() { return "admin"; }
}
