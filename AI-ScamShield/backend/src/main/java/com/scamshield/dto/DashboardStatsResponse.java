package com.scamshield.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DashboardStatsResponse {
    private long totalScans;
    private long safeCount;
    private long suspiciousCount;
    private long likelyScamCount;
    private double averageRiskScore;
    private List<ScanResultResponse> recentScans;
    private Map<String, Long> scamTypeDistribution;
    private List<RiskTrendPoint> riskTrend;
    private List<ThreatCountResponse> topDetectedThreats;
    private List<ScanResultResponse> highRiskScans;
}
