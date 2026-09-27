package com.scamshield.service.ai;

/**
 * Thin abstraction over whichever external LLM provider is configured
 * (e.g. Anthropic's Messages API). Kept separate from ScamDetectionService
 * so a different provider/model can be plugged in later without touching
 * business logic.
 */
public interface AiProviderClient {

    /**
     * Sends the given prompt to the configured LLM and returns the raw text
     * response. Implementations should throw
     * {@link com.scamshield.exception.AiServiceException} on any failure
     * (timeout, non-2xx, malformed response) so the caller can fall back.
     */
    String complete(String systemPrompt, String userPrompt);

    boolean isEnabled();
}
