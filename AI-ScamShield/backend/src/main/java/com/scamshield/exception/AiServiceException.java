package com.scamshield.exception;

/**
 * Thrown when the external AI provider call fails.
 * Callers should catch this and fall back to FallbackScamDetectionService.
 */
public class AiServiceException extends RuntimeException {
    public AiServiceException(String message, Throwable cause) {
        super(message, cause);
    }

    public AiServiceException(String message) {
        super(message);
    }
}
