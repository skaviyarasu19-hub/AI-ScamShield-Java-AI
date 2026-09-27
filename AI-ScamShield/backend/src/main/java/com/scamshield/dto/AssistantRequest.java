package com.scamshield.dto;

import com.scamshield.entity.MessageType;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class AssistantRequest {
    private Long scanId;

    @Size(max = 10000, message = "Content must be 10,000 characters or fewer")
    private String content;

    private MessageType messageType;

    @NotBlank(message = "Ask a question about the scan")
    @Size(max = 500, message = "Question must be 500 characters or fewer")
    private String question;

    @AssertTrue(message = "Provide a scan ID or both content and message type")
    public boolean isInputValid() {
        if (scanId != null) return true;
        return content != null && !content.isBlank() && messageType != null
                && (messageType != MessageType.URL || content.length() <= 2048);
    }
}
