package com.scamshield.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class FeedbackRequest {
    @NotNull
    private Long scanId;

    @NotNull
    private Boolean confirmedScam;

    private String comment;
}
