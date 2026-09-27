package com.scamshield.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UrlScanRequest {
    @NotBlank(message = "URL must not be empty")
    @Size(max = 2048, message = "URL must be 2,048 characters or fewer")
    private String url;
}
