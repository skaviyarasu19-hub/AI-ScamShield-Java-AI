package com.scamshield.service.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.scamshield.exception.AiServiceException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Concrete AiProviderClient implementation targeting the Anthropic Messages
 * API. Only used when ai.provider.enabled=true and an API key is present;
 * otherwise ScamDetectionOrchestrator routes straight to the fallback engine.
 *
 * The provider URL, model name and API key are all externally configurable
 * (see application.properties / .env.example) so a different LLM provider
 * can be swapped in later by implementing AiProviderClient again.
 */
@Component
public class AnthropicAiProviderClient implements AiProviderClient {

    @Value("${ai.provider.enabled}")
    private boolean enabled;

    @Value("${ai.provider.api-key}")
    private String apiKey;

    @Value("${ai.provider.url}")
    private String providerUrl;

    @Value("${ai.provider.model}")
    private String model;

    @Value("${ai.provider.timeout-ms}")
    private long timeoutMs;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean isEnabled() {
        return enabled && apiKey != null && !apiKey.isBlank();
    }

    @Override
    public String complete(String systemPrompt, String userPrompt) {
        if (!isEnabled()) {
            throw new AiServiceException("AI provider is not enabled or API key is missing");
        }

        try {
            RestClient client = RestClient.builder()
                    .baseUrl(providerUrl)
                    .requestFactory(clientHttpRequestFactory())
                    .build();

            Map<String, Object> body = Map.of(
                    "model", model,
                    "max_tokens", 1000,
                    "system", systemPrompt,
                    "messages", List.of(
                            Map.of("role", "user", "content", userPrompt)
                    )
            );

            String rawResponse = client.post()
                    .uri("")
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .header("x-api-key", apiKey)
                    .header("anthropic-version", "2023-06-01")
                    .body(body)
                    .retrieve()
                    .body(String.class);

            JsonNode root = objectMapper.readTree(rawResponse);
            JsonNode contentArray = root.path("content");
            StringBuilder text = new StringBuilder();
            if (contentArray.isArray()) {
                for (JsonNode block : contentArray) {
                    if ("text".equals(block.path("type").asText())) {
                        text.append(block.path("text").asText());
                    }
                }
            }

            if (text.isEmpty()) {
                throw new AiServiceException("AI provider returned an empty response");
            }

            return text.toString();

        } catch (AiServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new AiServiceException("AI provider call failed: " + e.getMessage(), e);
        }
    }

    private org.springframework.http.client.ClientHttpRequestFactory clientHttpRequestFactory() {
        org.springframework.http.client.SimpleClientHttpRequestFactory factory =
                new org.springframework.http.client.SimpleClientHttpRequestFactory();
        factory.setConnectTimeout((int) timeoutMs);
        factory.setReadTimeout((int) timeoutMs);
        return factory;
    }
}
