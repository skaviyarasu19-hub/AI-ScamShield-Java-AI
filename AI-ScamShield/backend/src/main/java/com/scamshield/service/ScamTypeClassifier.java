package com.scamshield.service;

import com.scamshield.entity.MessageType;
import com.scamshield.entity.RiskLevel;
import com.scamshield.entity.ScamType;
import com.scamshield.service.ai.ScamAnalysisResult;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class ScamTypeClassifier {

    public ScamType classify(MessageType messageType, List<ScamAnalysisResult.Indicator> indicators) {
        return classify(messageType, indicators, RiskLevel.LIKELY_SCAM);
    }

    public ScamType classify(MessageType messageType, List<ScamAnalysisResult.Indicator> indicators,
                             RiskLevel classification) {
        if (indicators == null || indicators.isEmpty()) {
            return ScamType.OTHER;
        }
        if (messageType == MessageType.URL && classification == RiskLevel.SAFE) {
            return ScamType.OTHER;
        }

        List<String> codes = indicators.stream()
                .map(ScamAnalysisResult.Indicator::getCode)
                .filter(code -> code != null)
                .toList();

        if (contains(codes, "CRED_OTP")) return ScamType.OTP_SCAM;
        if (contains(codes, "FIN_BANK")) return ScamType.BANKING_SCAM;
        if (contains(codes, "REWARD_")) return ScamType.FAKE_REWARD;
        if (contains(codes, "JOB_")) return ScamType.JOB_SCAM;
        if (contains(codes, "FIN_INVESTMENT")) return ScamType.INVESTMENT_SCAM;
        if (contains(codes, "IMPERSONATION_")) return ScamType.IMPERSONATION;
        if (messageType == MessageType.URL && codes.stream().anyMatch(code ->
                code.equals("URL_IP_HOST") || code.equals("URL_SHORTENER")
                        || code.equals("URL_SUSPICIOUS_KEYWORDS") || code.equals("URL_HYPHEN_HEAVY")
                        || code.equals("URL_ENCODED_CHARS") || code.equals("URL_AT_SYMBOL_TRICK")
                        || code.equals("URL_EXCESSIVE_SUBDOMAINS") || code.equals("URL_MALFORMED")
                        || code.equals("URL_PUNYCODE_HOST") || code.equals("URL_SUSPICIOUS_QUERY")
                        || code.equals("URL_EXCESSIVE_SPECIAL_CHARS"))) {
            return ScamType.MALICIOUS_LINK;
        }
        if (codes.stream().anyMatch(code -> code.startsWith("LINK_")
                || messageType != MessageType.URL && code.startsWith("URL_"))) {
            return ScamType.PHISHING;
        }
        if (contains(codes, "CRED_") || contains(codes, "PII_")) {
            return ScamType.PHISHING;
        }
        return ScamType.OTHER;
    }

    private boolean contains(List<String> codes, String prefix) {
        return codes.stream().anyMatch(code -> code.startsWith(prefix));
    }
}
