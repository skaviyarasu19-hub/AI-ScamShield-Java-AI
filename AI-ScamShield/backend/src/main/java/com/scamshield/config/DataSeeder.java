package com.scamshield.config;

import com.scamshield.entity.Role;
import com.scamshield.entity.RoleName;
import com.scamshield.entity.User;
import com.scamshield.repository.RoleRepository;
import com.scamshield.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

/**
 * Seeds default roles and a default admin/test user on first startup so the
 * project can be evaluated immediately without manual SQL inserts.
 */
@Component
@RequiredArgsConstructor
public class DataSeeder implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                .orElseGet(() -> roleRepository.save(Role.builder().name(RoleName.ROLE_USER).build()));

        Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
                .orElseGet(() -> roleRepository.save(Role.builder().name(RoleName.ROLE_ADMIN).build()));

        if (!userRepository.existsByUsername("admin")) {
            Set<Role> roles = new HashSet<>();
            roles.add(adminRole);
            roles.add(userRole);

            User admin = User.builder()
                    .username("admin")
                    .email("admin@scamshield.local")
                    .password(passwordEncoder.encode("Admin@123"))
                    .enabled(true)
                    .roles(roles)
                    .build();
            userRepository.save(admin);
        }

        if (!userRepository.existsByUsername("testuser")) {
            Set<Role> roles = new HashSet<>();
            roles.add(userRole);

            User testUser = User.builder()
                    .username("testuser")
                    .email("testuser@scamshield.local")
                    .password(passwordEncoder.encode("Test@123"))
                    .enabled(true)
                    .roles(roles)
                    .build();
            userRepository.save(testUser);
        }
    }
}
