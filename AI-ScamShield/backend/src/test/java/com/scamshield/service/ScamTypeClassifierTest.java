package com.scamshield.service;

import com.scamshield.entity.MessageType;
import com.scamshield.entity.RiskLevel;
import com.scamshield.entity.ScamType;
import com.scamshield.service.ai.ScamAnalysisResult;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ScamTypeClassifierTest {

    private final ScamTypeClassifier classifier = new ScamTypeClassifier();

    @Test
    void categorizesOtpRequestsByDetectedIndicator() {
        assertEquals(ScamType.OTP_SCAM, classifier.classify(MessageType.SMS, List.of(indicator("CRED_OTP_REQUEST"))));
    }

    @Test
    void httpsAbsenceAloneDoesNotLabelUrlAsMalicious() {
        assertEquals(ScamType.OTHER, classifier.classify(
                MessageType.URL, List.of(indicator("URL_NO_HTTPS")), RiskLevel.SAFE));
    }

    @Test
    void suspiciousUrlStructureGetsLinkCategory() {
        assertEquals(ScamType.MALICIOUS_LINK, classifier.classify(
                MessageType.URL, List.of(indicator("URL_IP_HOST")), RiskLevel.LIKELY_SCAM));
    }

    private ScamAnalysisResult.Indicator indicator(String code) {
        return ScamAnalysisResult.Indicator.builder().code(code).description(code).weight(10).build();
    }
}
