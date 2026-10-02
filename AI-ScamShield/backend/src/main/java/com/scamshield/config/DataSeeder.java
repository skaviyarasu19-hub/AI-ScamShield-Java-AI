package com.scamshield.config;

import com.scamshield.entity.Role;
import com.scamshield.entity.RoleName;
import com.scamshield.entity.User;
import com.scamshield.repository.RoleRepository;
import com.scamshield.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

/**
 * Seeds roles on startup and creates an admin only when credentials are supplied
 * through environment-backed configuration.
 */
@Component
@RequiredArgsConstructor
public class DataSeeder implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.seed.admin.username:}")
    private String adminUsername;

    @Value("${app.seed.admin.email:}")
    private String adminEmail;

    @Value("${app.seed.admin.password:}")
    private String adminPassword;

    @Override
    public void run(String... args) {
        Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                .orElseGet(() -> roleRepository.save(Role.builder().name(RoleName.ROLE_USER).build()));

        Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
                .orElseGet(() -> roleRepository.save(Role.builder().name(RoleName.ROLE_ADMIN).build()));

        boolean adminConfigured = hasText(adminUsername) && hasText(adminEmail) && hasText(adminPassword);
        boolean anyAdminSettingConfigured = hasText(adminUsername) || hasText(adminEmail) || hasText(adminPassword);
        if (anyAdminSettingConfigured && !adminConfigured) {
            throw new IllegalStateException("Configure all SEED_ADMIN_USERNAME, SEED_ADMIN_EMAIL, and SEED_ADMIN_PASSWORD values");
        }

        if (adminConfigured && !userRepository.existsByUsername(adminUsername)
                && !userRepository.existsByEmail(adminEmail)) {
            Set<Role> roles = new HashSet<>();
            roles.add(adminRole);
            roles.add(userRole);

            User admin = User.builder()
                    .username(adminUsername)
                    .email(adminEmail)
                    .password(passwordEncoder.encode(adminPassword))
                    .enabled(true)
                    .roles(roles)
                    .build();
            userRepository.save(admin);
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
