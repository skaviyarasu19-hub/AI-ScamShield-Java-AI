package com.scamshield.service;

import com.scamshield.dto.FeedbackRequest;
import com.scamshield.entity.Feedback;
import com.scamshield.entity.Scan;
import com.scamshield.entity.User;
import com.scamshield.exception.ResourceNotFoundException;
import com.scamshield.exception.UnauthorizedException;
import com.scamshield.repository.FeedbackRepository;
import com.scamshield.repository.ScanRepository;
import com.scamshield.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Records user feedback on scan results ("this was actually a scam" /
 * "this was safe"). The feedback is persisted alongside the original scan
 * so that a future training/fine-tuning pipeline could use it to improve
 * the detection model — that pipeline is out of scope for this project,
 * but the data model is designed to support it.
 */
@Service
@RequiredArgsConstructor
public class FeedbackService {

    private final FeedbackRepository feedbackRepository;
    private final ScanRepository scanRepository;
    private final UserRepository userRepository;

    public void submitFeedback(String username, FeedbackRequest request) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        Scan scan = scanRepository.findById(request.getScanId())
                .orElseThrow(() -> new ResourceNotFoundException("Scan not found"));

        if (!scan.getUser().getId().equals(user.getId())) {
            throw new UnauthorizedException("You can only give feedback on your own scans");
        }

        Feedback feedback = Feedback.builder()
                .scan(scan)
                .user(user)
                .confirmedScam(Boolean.TRUE.equals(request.getConfirmedScam()))
                .comment(request.getComment())
                .build();

        feedbackRepository.save(feedback);
    }
}
