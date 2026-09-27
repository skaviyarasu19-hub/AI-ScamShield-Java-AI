package com.scamshield.service;

import com.scamshield.dto.AssistantRequest;
import com.scamshield.dto.AssistantResponse;
import com.scamshield.dto.ScanResultResponse;
import com.scamshield.entity.MessageType;
import com.scamshield.entity.ScamType;
import com.scamshield.service.ai.ScamAnalysisResult;
import com.scamshield.service.ai.ScamDetectionOrchestrator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AiAssistantService {

    private final ScanService scanService;
    private final ScamDetectionOrchestrator orchestrator;
    private final ScamTypeClassifier scamTypeClassifier;

    public AssistantResponse answer(String username, AssistantRequest request) {
        if (request.getScanId() != null) {
            return fromSavedScan(scanService.getScanById(username, request.getScanId()));
        }

        ScamDetectionOrchestrator.EngineResult engineResult;
        if (request.getMessageType() == MessageType.URL) {
            engineResult = orchestrator.analyzeUrl(request.getContent());
        } else {
            engineResult = orchestrator.analyzeMessage(request.getContent(), null, request.getMessageType());
        }

        ScamAnalysisResult analysis = engineResult.result();
        ScamType scamType = scamTypeClassifier.classify(request.getMessageType(), analysis.getIndicators(),
                analysis.getClassification());
        int confidence = calculateConfidence(analysis.getIndicators());
        List<String> risks = analysis.getIndicators().stream()
                .map(ScamAnalysisResult.Indicator::getDescription)
                .toList();

        String label = switch (analysis.getClassification()) {
            case SAFE -> "low risk";
            case SUSPICIOUS -> "suspicious";
            case LIKELY_SCAM -> "likely scam";
        };
        String summary = risks.isEmpty()
                ? "No strong scam indicators were detected. This does not guarantee the content is safe."
                : "The analysis classifies this as " + label + " (" + analysis.getRiskScore()
                + "/100), based on " + risks.size() + " detected indicator(s).";

        return AssistantResponse.builder()
                .shortAnswer(summary)
                .detectedRisks(risks)
                .explanation(analysis.getExplanation())
                .recommendation(analysis.getRecommendation())
                .classification(analysis.getClassification().name())
                .riskScore(analysis.getRiskScore())
                .scamType(scamType)
                .confidenceScore(confidence)
                .analysisEngine(engineResult.engineName())
                .build();
    }

    private AssistantResponse fromSavedScan(ScanResultResponse scan) {
        List<String> risks = scan.getIndicators().stream()
                .map(indicator -> indicator.getDescription())
                .toList();
        String label = switch (scan.getClassification()) {
            case SAFE -> "low risk";
            case SUSPICIOUS -> "suspicious";
            case LIKELY_SCAM -> "likely scam";
        };
        String summary = risks.isEmpty()
                ? "No strong scam indicators were detected. This does not guarantee the content is safe."
                : "The analysis classifies this as " + label + " (" + scan.getRiskScore()
                + "/100), based on " + risks.size() + " detected indicator(s).";

        return AssistantResponse.builder()
                .shortAnswer(summary)
                .detectedRisks(risks)
                .explanation(scan.getExplanation())
                .recommendation(scan.getRecommendation())
                .classification(scan.getClassification().name())
                .riskScore(scan.getRiskScore())
                .scamType(scan.getScamType())
                .confidenceScore(scan.getConfidenceScore())
                .analysisEngine(scan.getAnalysisEngine())
                .build();
    }

    private int calculateConfidence(List<ScamAnalysisResult.Indicator> indicators) {
        if (indicators == null || indicators.isEmpty()) return 0;
        int totalWeight = indicators.stream().mapToInt(ScamAnalysisResult.Indicator::getWeight).sum();
        int distinctSignals = (int) indicators.stream().map(ScamAnalysisResult.Indicator::getCode).distinct().count();
        return Math.min(98, 52 + Math.min(30, distinctSignals * 6) + Math.min(16, totalWeight / 8));
    }
}
