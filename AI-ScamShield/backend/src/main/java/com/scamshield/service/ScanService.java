package com.scamshield.service;

import com.scamshield.dto.*;
import com.scamshield.entity.*;
import com.scamshield.exception.BadRequestException;
import com.scamshield.exception.ResourceNotFoundException;
import com.scamshield.exception.UnauthorizedException;
import com.scamshield.repository.ScanRepository;
import com.scamshield.repository.UserRepository;
import com.scamshield.service.ai.ScamAnalysisResult;
import com.scamshield.service.ai.ScamDetectionOrchestrator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ScanService {

    private final ScanRepository scanRepository;
    private final UserRepository userRepository;
    private final ScamDetectionOrchestrator orchestrator;
    private final ScamTypeClassifier scamTypeClassifier;

    public ScanResultResponse analyzeMessage(String username, MessageScanRequest request) {
        User user = getUser(username);

        ScamDetectionOrchestrator.EngineResult engineResult =
                orchestrator.analyzeMessage(request.getContent(), request.getSenderInfo(), request.getMessageType());

        Scan scan = persistScan(user, request.getMessageType(), request.getSenderInfo(), request.getContent(), engineResult);
        return toResponse(scan);
    }

    public ScanResultResponse analyzeUrl(String username, UrlScanRequest request) {
        User user = getUser(username);

        ScamDetectionOrchestrator.EngineResult engineResult = orchestrator.analyzeUrl(request.getUrl());

        Scan scan = persistScan(user, MessageType.URL, null, request.getUrl(), engineResult);
        return toResponse(scan);
    }

    @Transactional(readOnly = true)
    public List<ScanResultResponse> getHistory(String username, RiskLevel riskLevelFilter,
                                                MessageType messageType, String scamTypeFilter,
                                                String search, String sortBy, boolean ascending) {
        User user = getUser(username);
        List<Scan> scans = riskLevelFilter == null
                ? scanRepository.findByUserOrderByCreatedAtDesc(user)
                : scanRepository.findByUserAndClassificationOrderByCreatedAtDesc(user, riskLevelFilter);

        ScamType requestedType = null;
        if (scamTypeFilter != null && !scamTypeFilter.isBlank()) {
            try {
                requestedType = ScamType.valueOf(scamTypeFilter.toUpperCase());
            } catch (IllegalArgumentException exception) {
                throw new BadRequestException("Unknown scam type filter");
            }
        }
        final ScamType selectedType = requestedType;
        String normalizedSearch = search == null ? "" : search.trim().toLowerCase();

        Comparator<ScanResultResponse> comparator = "RISK".equalsIgnoreCase(sortBy)
                ? Comparator.comparingInt(ScanResultResponse::getRiskScore)
                : Comparator.comparing(ScanResultResponse::getCreatedAt);
        if (!ascending) comparator = comparator.reversed();

        return scans.stream()
                .map(this::toResponse)
                .filter(scan -> messageType == null || scan.getMessageType() == messageType)
                .filter(scan -> selectedType == null || scan.getScamType() == selectedType)
                .filter(scan -> normalizedSearch.isEmpty()
                        || scan.getContent().toLowerCase().contains(normalizedSearch)
                        || scan.getIndicators().stream().anyMatch(i ->
                        i.getDescription().toLowerCase().contains(normalizedSearch)))
                .sorted(comparator)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public ScanResultResponse getScanById(String username, Long scanId) {
        User user = getUser(username);
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new ResourceNotFoundException("Scan not found"));

        if (!scan.getUser().getId().equals(user.getId())) {
            throw new UnauthorizedException("You do not have access to this scan");
        }
        return toResponse(scan);
    }

    public void deleteScan(String username, Long scanId) {
        User user = getUser(username);
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new ResourceNotFoundException("Scan not found"));

        if (!scan.getUser().getId().equals(user.getId())) {
            throw new UnauthorizedException("You do not have access to this scan");
        }
        scanRepository.delete(scan);
    }

    @Transactional(readOnly = true)
    public DashboardStatsResponse getDashboardStats(String username) {
        User user = getUser(username);

        long total = scanRepository.countByUser(user);
        long safe = scanRepository.countByUserAndClassification(user, RiskLevel.SAFE);
        long suspicious = scanRepository.countByUserAndClassification(user, RiskLevel.SUSPICIOUS);
        long likelyScam = scanRepository.countByUserAndClassification(user, RiskLevel.LIKELY_SCAM);

        List<Scan> allScans = scanRepository.findByUserOrderByCreatedAtDesc(user);
        double avgRisk = allScans.isEmpty() ? 0.0
                : allScans.stream().mapToInt(Scan::getRiskScore).average().orElse(0.0);

        List<ScanResultResponse> recent = allScans.stream()
                .limit(5)
                .map(this::toResponse)
                .collect(Collectors.toList());

        Map<String, Long> scamTypeDistribution = new LinkedHashMap<>();
        for (ScamType type : ScamType.values()) scamTypeDistribution.put(type.name(), 0L);
        allScans.stream()
                .map(this::toResponse)
                .forEach(scan -> scamTypeDistribution.compute(
                        scan.getScamType().name(), (key, value) -> value + 1));

        LocalDate today = LocalDate.now();
        Map<LocalDate, List<Scan>> scansByDate = allScans.stream()
                .filter(scan -> scan.getCreatedAt().toLocalDate().isAfter(today.minusDays(7)))
                .collect(Collectors.groupingBy(scan -> scan.getCreatedAt().toLocalDate()));
        List<RiskTrendPoint> riskTrend = java.util.stream.IntStream.rangeClosed(0, 6)
                .mapToObj(offset -> today.minusDays(6L - offset))
                .map(date -> {
                    List<Scan> dayScans = scansByDate.getOrDefault(date, List.of());
                    return RiskTrendPoint.builder()
                            .date(date)
                            .total(dayScans.size())
                            .safe(dayScans.stream().filter(scan -> scan.getClassification() == RiskLevel.SAFE).count())
                            .suspicious(dayScans.stream().filter(scan -> scan.getClassification() == RiskLevel.SUSPICIOUS).count())
                            .likelyScam(dayScans.stream().filter(scan -> scan.getClassification() == RiskLevel.LIKELY_SCAM).count())
                            .build();
                }).toList();

        Map<String, ThreatCountResponse> threatsByCode = new LinkedHashMap<>();
        allScans.stream().flatMap(scan -> scan.getIndicators().stream()).forEach(indicator ->
                threatsByCode.compute(indicator.getCode(), (code, existing) -> existing == null
                        ? ThreatCountResponse.builder().code(code).description(indicator.getDescription()).count(1).build()
                        : ThreatCountResponse.builder().code(code).description(existing.getDescription())
                        .count(existing.getCount() + 1).build()));
        List<ThreatCountResponse> topThreats = threatsByCode.values().stream()
                .sorted(Comparator.comparingLong(ThreatCountResponse::getCount).reversed())
                .limit(5)
                .toList();
        List<ScanResultResponse> highRiskScans = allScans.stream()
                .filter(scan -> scan.getRiskScore() >= 60)
                .limit(5)
                .map(this::toResponse)
                .toList();

        return DashboardStatsResponse.builder()
                .totalScans(total)
                .safeCount(safe)
                .suspiciousCount(suspicious)
                .likelyScamCount(likelyScam)
                .averageRiskScore(Math.round(avgRisk * 100.0) / 100.0)
                .recentScans(recent)
                .scamTypeDistribution(scamTypeDistribution)
                .riskTrend(riskTrend)
                .topDetectedThreats(topThreats)
                .highRiskScans(highRiskScans)
                .build();
    }

    // ---------------------------------------------------------------------

    private Scan persistScan(User user, MessageType type, String senderInfo, String content,
                              ScamDetectionOrchestrator.EngineResult engineResult) {
        ScamAnalysisResult result = engineResult.result();
        ScamType scamType = scamTypeClassifier.classify(type, result.getIndicators(), result.getClassification());
        int confidence = calculateConfidence(result.getIndicators());

        Scan scan = Scan.builder()
                .user(user)
                .messageType(type)
                .senderInfo(senderInfo)
                .content(content)
                .classification(result.getClassification())
                .riskScore(result.getRiskScore())
                .scamType(scamType)
                .confidenceScore(confidence)
                .explanation(result.getExplanation())
                .recommendation(result.getRecommendation())
                .analysisEngine(engineResult.engineName())
                .build();

        List<ScanIndicator> indicators = result.getIndicators().stream()
                .map(ind -> ScanIndicator.builder()
                        .scan(scan)
                        .code(ind.getCode())
                        .description(ind.getDescription())
                        .weight(ind.getWeight())
                        .build())
                .collect(Collectors.toList());

        scan.setIndicators(indicators);

        return scanRepository.save(scan);
    }

    private ScanResultResponse toResponse(Scan scan) {
        List<ScanIndicatorDto> indicatorDtos = scan.getIndicators().stream()
                .map(i -> ScanIndicatorDto.builder()
                        .code(i.getCode())
                        .description(i.getDescription())
                        .weight(i.getWeight())
                        .build())
                .collect(Collectors.toList());

        ScamType scamType = scan.getScamType() != null ? scan.getScamType()
                : scamTypeClassifier.classify(scan.getMessageType(), scan.getIndicators().stream()
                .map(i -> ScamAnalysisResult.Indicator.builder()
                        .code(i.getCode())
                        .description(i.getDescription())
                        .weight(i.getWeight())
                        .build())
                .toList(), scan.getClassification());

        return ScanResultResponse.builder()
                .id(scan.getId())
                .messageType(scan.getMessageType())
                .content(scan.getContent())
                .classification(scan.getClassification())
                .riskScore(scan.getRiskScore())
                .confidenceScore(scan.getConfidenceScore() != null && scan.getConfidenceScore() > 0 ? scan.getConfidenceScore()
                        : calculateConfidence(scan.getIndicators().stream()
                        .map(i -> ScamAnalysisResult.Indicator.builder().code(i.getCode()).weight(i.getWeight()).build())
                        .toList()))
                .scamType(scamType)
                .riskLevelLabel(humanLabel(scan.getClassification()))
                .indicators(indicatorDtos)
                .explanation(scan.getExplanation())
                .technicalAnalysis(scan.getMessageType() == MessageType.URL ? scan.getExplanation() : null)
                .recommendation(scan.getRecommendation())
                .analysisEngine(scan.getAnalysisEngine())
                .createdAt(scan.getCreatedAt())
                .build();
    }

    private int calculateConfidence(List<ScamAnalysisResult.Indicator> indicators) {
        if (indicators == null || indicators.isEmpty()) return 0;
        int totalWeight = indicators.stream().mapToInt(ScamAnalysisResult.Indicator::getWeight).sum();
        int distinctSignals = (int) indicators.stream().map(ScamAnalysisResult.Indicator::getCode).distinct().count();
        return Math.min(98, 52 + Math.min(30, distinctSignals * 6) + Math.min(16, totalWeight / 8));
    }

    private String humanLabel(RiskLevel level) {
        return switch (level) {
            case SAFE -> "Safe";
            case SUSPICIOUS -> "Suspicious";
            case LIKELY_SCAM -> "Likely Scam";
        };
    }

    private User getUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }
}
