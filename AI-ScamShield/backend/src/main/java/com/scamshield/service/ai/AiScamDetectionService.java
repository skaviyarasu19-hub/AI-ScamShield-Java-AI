package com.scamshield.service.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.scamshield.entity.MessageType;
import com.scamshield.entity.RiskLevel;
import com.scamshield.exception.AiServiceException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * LLM-backed implementation of ScamDetectionService. Used only when
 * ai.provider.enabled=true and a valid API key is configured
 * (see AnthropicAiProviderClient / .env.example).
 *
 * The model is instructed to return strict JSON, which is parsed into the
 * same ScamAnalysisResult shape used by FallbackScamDetectionService, so the
 * rest of the application (controllers, persistence, frontend) never needs
 * to know which engine actually produced a given result.
 */
@Service
@RequiredArgsConstructor
public class AiScamDetectionService implements ScamDetectionService {

    private final AiProviderClient aiProviderClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private static final String SYSTEM_PROMPT = """
            You are a cybersecurity assistant that analyzes messages and URLs for scam risk.
            You must NEVER claim certainty that something is definitely a scam, and NEVER
            accuse a specific named individual of a crime. Use cautious wording such as
            "likely scam", "suspicious", or "low risk". Do not provide instructions for
            committing fraud. Respond ONLY with valid JSON matching this exact schema,
            with no markdown fences and no extra commentary:
            {
              "classification": "SAFE" | "SUSPICIOUS" | "LIKELY_SCAM",
              "riskScore": <integer 0-100>,
              "indicators": [ { "code": "SHORT_CODE", "description": "short description", "weight": <integer> } ],
              "explanation": "plain-language explanation of the reasoning",
              "recommendation": "safety guidance, no guarantees, no automatic actions"
            }
            """;

    @Override
    public String engineName() {
        return "AI_LLM";
    }

    @Override
    public ScamAnalysisResult analyzeMessage(String content, String senderInfo, MessageType messageType) {
        String userPrompt = """
                Analyze the following %s message for scam risk.
                Sender info: %s
                Message content:
                ---
                %s
                ---
                Consider: urgency/pressure tactics, financial requests, OTP/PIN/password requests,
                fake rewards, fake job offers, impersonation, account suspension threats,
                suspicious links, social engineering, and requests for personal information.
                Respond with the required JSON only.
                """.formatted(messageType, senderInfo == null ? "unknown" : senderInfo, content);

        return callAndParse(userPrompt);
    }

    @Override
    public ScamAnalysisResult analyzeUrl(String url) {
        String userPrompt = """
                Analyze the following URL for phishing/scam risk based on its structure
                (HTTPS usage, domain patterns, subdomains, IP-literal hosts, suspicious
                keywords, length, encoding). Do not attempt to crawl or access the URL.
                URL: %s
                Respond with the required JSON only.
                """.formatted(url);

        return callAndParse(userPrompt);
    }

    private ScamAnalysisResult callAndParse(String userPrompt) {
        String raw = aiProviderClient.complete(SYSTEM_PROMPT, userPrompt);

        try {
            String cleaned = raw.trim()
                    .replaceAll("^```json", "")
                    .replaceAll("^```", "")
                    .replaceAll("```$", "")
                    .trim();

            JsonNode node = objectMapper.readTree(cleaned);

            RiskLevel classification = RiskLevel.valueOf(node.path("classification").asText("SUSPICIOUS"));
            int riskScore = Math.max(0, Math.min(100, node.path("riskScore").asInt(50)));

            List<ScamAnalysisResult.Indicator> indicators = new ArrayList<>();
            JsonNode indicatorsNode = node.path("indicators");
            if (indicatorsNode.isArray()) {
                for (JsonNode ind : indicatorsNode) {
                    indicators.add(ScamAnalysisResult.Indicator.builder()
                            .code(ind.path("code").asText("AI_INDICATOR"))
                            .description(ind.path("description").asText(""))
                            .weight(ind.path("weight").asInt(5))
                            .build());
                }
            }

            String explanation = node.path("explanation").asText("The AI model flagged this content based on learned scam patterns.");
            String recommendation = node.path("recommendation").asText("Exercise caution and verify through official channels.");

            return ScamAnalysisResult.builder()
                    .classification(classification)
                    .riskScore(riskScore)
                    .indicators(indicators)
                    .explanation(explanation)
                    .recommendation(recommendation)
                    .build();

        } catch (Exception e) {
            throw new AiServiceException("Failed to parse AI provider response: " + e.getMessage(), e);
        }
    }
}
