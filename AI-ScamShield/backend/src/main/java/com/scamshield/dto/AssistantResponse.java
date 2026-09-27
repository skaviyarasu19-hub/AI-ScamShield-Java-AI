package com.scamshield.dto;

import com.scamshield.entity.ScamType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AssistantResponse {
    private String shortAnswer;
    private List<String> detectedRisks;
    private String explanation;
    private String recommendation;
    private String classification;
    private int riskScore;
    private ScamType scamType;
    private int confidenceScore;
    private String analysisEngine;
}
