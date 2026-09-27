package com.scamshield.controller;

import com.scamshield.dto.AssistantRequest;
import com.scamshield.dto.AssistantResponse;
import com.scamshield.service.AiAssistantService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/assistant")
@RequiredArgsConstructor
public class AiAssistantController {

    private final AiAssistantService assistantService;

    @PostMapping("/analyze")
    public ResponseEntity<AssistantResponse> analyze(Authentication auth,
                                                       @Valid @RequestBody AssistantRequest request) {
        return ResponseEntity.ok(assistantService.answer(auth.getName(), request));
    }
}
