package com.scamshield.service.ai;

import com.scamshield.entity.RiskLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

/**
 * Engine-agnostic result of a scam analysis, produced by either the
 * fallback rule-based NLP engine or a real LLM provider.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScamAnalysisResult {

    private RiskLevel classification;
    private int riskScore; // 0-100

    @Builder.Default
    private List<Indicator> indicators = new ArrayList<>();

    private String explanation;
    private String recommendation;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Indicator {
        private String code;
        private String description;
        private int weight;
    }
}
