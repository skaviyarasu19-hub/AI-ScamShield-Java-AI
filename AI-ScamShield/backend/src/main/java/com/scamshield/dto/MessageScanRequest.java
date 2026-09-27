package com.scamshield.dto;

import com.scamshield.entity.MessageType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class MessageScanRequest {
    @NotBlank(message = "Message content must not be empty")
    @Size(max = 10000, message = "Message content must be 10,000 characters or fewer")
    private String content;

    @Size(max = 150, message = "Sender information must be 150 characters or fewer")
    private String senderInfo;

    @NotNull(message = "Message type is required")
    private MessageType messageType; // SMS, WHATSAPP, EMAIL
}
