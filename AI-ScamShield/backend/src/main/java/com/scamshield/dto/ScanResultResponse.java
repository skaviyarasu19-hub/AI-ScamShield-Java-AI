package com.scamshield.dto;

import com.scamshield.entity.MessageType;
import com.scamshield.entity.RiskLevel;
import com.scamshield.entity.ScamType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScanResultResponse {
    private Long id;
    private MessageType messageType;
    private String content;
    private RiskLevel classification;
    private int riskScore;
    private int confidenceScore;
    private ScamType scamType;
    private String riskLevelLabel;
    private List<ScanIndicatorDto> indicators;
    private String explanation;
    private String technicalAnalysis;
    private String recommendation;
    private String analysisEngine;
    private LocalDateTime createdAt;
}
