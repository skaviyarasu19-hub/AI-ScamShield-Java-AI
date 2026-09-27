package com.scamshield.service.ai;

import com.scamshield.entity.MessageType;

/**
 * Abstraction over the scam-detection analysis engine. This allows the
 * concrete implementation to be swapped between a real LLM-backed provider
 * (AiScamDetectionService) and a local, fully offline rule-based NLP engine
 * (FallbackScamDetectionService) without changing any calling code.
 */
public interface ScamDetectionService {

    /**
     * Analyzes free-text message content (SMS / WhatsApp / Email).
     */
    ScamAnalysisResult analyzeMessage(String content, String senderInfo, MessageType messageType);

    /**
     * Analyzes a URL for phishing / scam characteristics.
     */
    ScamAnalysisResult analyzeUrl(String url);

    /**
     * A short machine-readable name identifying which engine produced the result,
     * e.g. "FALLBACK_NLP" or "AI_LLM". Stored alongside every scan for transparency.
     */
    String engineName();
}
