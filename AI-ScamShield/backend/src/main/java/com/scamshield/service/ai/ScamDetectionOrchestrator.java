package com.scamshield.service.ai;

import com.scamshield.entity.MessageType;
import com.scamshield.exception.AiServiceException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Chooses which ScamDetectionService implementation to use for a given
 * request, and transparently falls back to the local NLP engine if the
 * LLM provider is disabled, unconfigured, or fails/times out.
 *
 * This is the single entry point the rest of the application (services,
 * controllers) should depend on.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ScamDetectionOrchestrator {

    private final AiProviderClient aiProviderClient;
    private final AiScamDetectionService aiScamDetectionService;
    private final FallbackScamDetectionService fallbackScamDetectionService;

    public EngineResult analyzeMessage(String content, String senderInfo, MessageType messageType) {
        if (aiProviderClient.isEnabled()) {
            try {
                ScamAnalysisResult result = aiScamDetectionService.analyzeMessage(content, senderInfo, messageType);
                return new EngineResult(result, aiScamDetectionService.engineName());
            } catch (AiServiceException e) {
                log.warn("AI provider failed, falling back to local NLP engine: {}", e.getMessage());
            }
        }
        ScamAnalysisResult result = fallbackScamDetectionService.analyzeMessage(content, senderInfo, messageType);
        return new EngineResult(result, fallbackScamDetectionService.engineName());
    }

    public EngineResult analyzeUrl(String url) {
        if (aiProviderClient.isEnabled()) {
            try {
                ScamAnalysisResult result = aiScamDetectionService.analyzeUrl(url);
                return new EngineResult(result, aiScamDetectionService.engineName());
            } catch (AiServiceException e) {
                log.warn("AI provider failed, falling back to local NLP engine: {}", e.getMessage());
            }
        }
        ScamAnalysisResult result = fallbackScamDetectionService.analyzeUrl(url);
        return new EngineResult(result, fallbackScamDetectionService.engineName());
    }

    public record EngineResult(ScamAnalysisResult result, String engineName) {
    }
}
