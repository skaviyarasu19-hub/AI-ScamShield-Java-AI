package com.scamshield.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RiskTrendPoint {
    private LocalDate date;
    private long total;
    private long safe;
    private long suspicious;
    private long likelyScam;
}
