package com.scamshield.service;

import com.scamshield.entity.MessageType;
import com.scamshield.entity.RiskLevel;
import com.scamshield.service.ai.FallbackScamDetectionService;
import com.scamshield.service.ai.ScamAnalysisProperties;
import com.scamshield.service.ai.ScamAnalysisResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FallbackScamDetectionServiceTest {

    private final FallbackScamDetectionService service =
            new FallbackScamDetectionService(new ScamAnalysisProperties());

    @Test
    void safeMessage_isClassifiedSafe() {
        ScamAnalysisResult result = service.analyzeMessage(
                "Hi, are we still meeting for lunch at 1pm tomorrow?", "Mom", MessageType.SMS);

        assertEquals(RiskLevel.SAFE, result.getClassification());
        assertTrue(result.getRiskScore() < 25);
    }

    @Test
    void lotteryScamWithUrgencyAndFee_isClassifiedLikelyScam() {
        String message = "Congratulations! You have won a lottery of $1,000,000!!! " +
                "Pay a small processing fee immediately to claim your prize before it expires today. " +
                "Send your bank account number and OTP now.";

        ScamAnalysisResult result = service.analyzeMessage(message, "LOTTERY-WIN", MessageType.SMS);

        assertEquals(RiskLevel.LIKELY_SCAM, result.getClassification());
        assertTrue(result.getRiskScore() >= 60);
        assertFalse(result.getIndicators().isEmpty());
    }

    @Test
    void otpRequest_isFlagged() {
        ScamAnalysisResult result = service.analyzeMessage(
                "Your bank account will be suspended. Please share your OTP immediately to verify your account.",
                "BANK-ALERT", MessageType.SMS);

        assertTrue(result.getRiskScore() >= 25);
        assertTrue(result.getIndicators().stream().anyMatch(i -> i.getCode().equals("CRED_OTP_REQUEST")));
    }

    @Test
    void phishingMessageWithCredentialLink_isClassifiedAsHighRisk() {
        ScamAnalysisResult result = service.analyzeMessage(
                "Your bank account has been suspended. Verify your account immediately at http://192.168.1.55/secure-login/verify-account or your funds will be blocked. Share your password and OTP.",
                null, MessageType.EMAIL);

        assertEquals(RiskLevel.LIKELY_SCAM, result.getClassification());
        assertTrue(result.getIndicators().stream().anyMatch(i -> i.getCode().equals("CRED_LOGIN_UPDATE")));
        assertTrue(result.getIndicators().stream().anyMatch(i -> i.getCode().equals("LINK_SUSPICIOUS")));
    }

    @Test
    void ipLiteralUrl_isRiskier() {
        ScamAnalysisResult httpsResult = service.analyzeUrl("https://www.google.com");
        ScamAnalysisResult ipResult = service.analyzeUrl("http://192.168.1.55/secure-login/verify-account");

        assertTrue(ipResult.getRiskScore() > httpsResult.getRiskScore());
        assertEquals(RiskLevel.LIKELY_SCAM, ipResult.getClassification());
    }

    @Test
    void wellFormedHttpsUrl_isSafe() {
        ScamAnalysisResult result = service.analyzeUrl("https://www.wikipedia.org/wiki/Computer_science");
        assertEquals(RiskLevel.SAFE, result.getClassification());
    }

    @Test
    void configuredFeatureWeights_changeDeterministicRiskScore() {
        ScamAnalysisProperties properties = new ScamAnalysisProperties();
        properties.getWeights().setCredential(2.0);
        FallbackScamDetectionService weightedService = new FallbackScamDetectionService(properties);

        ScamAnalysisResult result = weightedService.analyzeMessage(
                "Please share your OTP", null, MessageType.SMS);

        assertEquals(40, result.getRiskScore());
        assertEquals(RiskLevel.SUSPICIOUS, result.getClassification());
    }

    @Test
    void suspiciousRedirectQueryIsReportedAsAnIndicator() {
        ScamAnalysisResult result = service.analyzeUrl("https://example.com/?redirect=https%3A%2F%2Fother.test");

        assertTrue(result.getIndicators().stream().anyMatch(i -> i.getCode().equals("URL_SUSPICIOUS_QUERY")));
    }
}
