package com.scamshield.controller;

import com.scamshield.dto.FeedbackRequest;
import com.scamshield.service.FeedbackService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/feedback")
@RequiredArgsConstructor
public class FeedbackController {

    private final FeedbackService feedbackService;

    @PostMapping
    public ResponseEntity<Void> submitFeedback(Authentication auth, @Valid @RequestBody FeedbackRequest request) {
        feedbackService.submitFeedback(auth.getName(), request);
        return ResponseEntity.ok().build();
    }
}
