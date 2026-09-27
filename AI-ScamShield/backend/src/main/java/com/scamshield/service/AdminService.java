package com.scamshield.service;

import com.scamshield.dto.AdminStatsResponse;
import com.scamshield.dto.UserSummaryResponse;
import com.scamshield.entity.RiskLevel;
import com.scamshield.entity.User;
import com.scamshield.exception.ResourceNotFoundException;
import com.scamshield.repository.ScanRepository;
import com.scamshield.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final UserRepository userRepository;
    private final ScanRepository scanRepository;

    public AdminStatsResponse getStatistics() {
        List<User> users = userRepository.findAll();
        long totalUsers = users.size();
        long activeUsers = users.stream().filter(User::isEnabled).count();

        long totalScans = scanRepository.count();
        long safe = scanRepository.countByClassification(RiskLevel.SAFE);
        long suspicious = scanRepository.countByClassification(RiskLevel.SUSPICIOUS);
        long likelyScam = scanRepository.countByClassification(RiskLevel.LIKELY_SCAM);

        return AdminStatsResponse.builder()
                .totalUsers(totalUsers)
                .activeUsers(activeUsers)
                .totalScans(totalScans)
                .safeCount(safe)
                .suspiciousCount(suspicious)
                .likelyScamCount(likelyScam)
                .build();
    }

    public List<UserSummaryResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(u -> UserSummaryResponse.builder()
                        .id(u.getId())
                        .username(u.getUsername())
                        .email(u.getEmail())
                        .enabled(u.isEnabled())
                        .roles(u.getRoles().stream().map(r -> r.getName().name()).collect(Collectors.toList()))
                        .createdAt(u.getCreatedAt())
                        .totalScans(scanRepository.countByUser(u))
                        .build())
                .collect(Collectors.toList());
    }

    public void setUserEnabled(Long userId, boolean enabled) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        user.setEnabled(enabled);
        userRepository.save(user);
    }
}
