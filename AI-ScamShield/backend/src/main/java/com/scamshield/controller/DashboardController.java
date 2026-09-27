package com.scamshield.controller;

import com.scamshield.dto.DashboardStatsResponse;
import com.scamshield.dto.RiskTrendPoint;
import com.scamshield.service.ScanService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
public class DashboardController {

    private final ScanService scanService;

    @GetMapping
    public ResponseEntity<DashboardStatsResponse> getDashboard(Authentication auth) {
        return ResponseEntity.ok(scanService.getDashboardStats(auth.getName()));
    }

    @GetMapping("/stats")
    public ResponseEntity<DashboardStatsResponse> getStats(Authentication auth) {
        return getDashboard(auth);
    }

    @GetMapping("/trends")
    public ResponseEntity<List<RiskTrendPoint>> getTrends(Authentication auth) {
        return ResponseEntity.ok(scanService.getDashboardStats(auth.getName()).getRiskTrend());
    }

    @GetMapping("/scam-types")
    public ResponseEntity<Map<String, Long>> getScamTypes(Authentication auth) {
        return ResponseEntity.ok(scanService.getDashboardStats(auth.getName()).getScamTypeDistribution());
    }
}
