package com.scamshield.controller;

import com.scamshield.dto.MessageScanRequest;
import com.scamshield.dto.ScanResultResponse;
import com.scamshield.dto.UrlScanRequest;
import com.scamshield.entity.RiskLevel;
import com.scamshield.entity.MessageType;
import com.scamshield.exception.BadRequestException;
import com.scamshield.service.ScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/scans")
@RequiredArgsConstructor
public class ScanController {

    private final ScanService scanService;

    @PostMapping("/message")
    public ResponseEntity<ScanResultResponse> analyzeMessage(Authentication auth,
                                                               @Valid @RequestBody MessageScanRequest request) {
        return ResponseEntity.ok(scanService.analyzeMessage(auth.getName(), request));
    }

    @PostMapping("/url")
    public ResponseEntity<ScanResultResponse> analyzeUrl(Authentication auth,
                                                           @Valid @RequestBody UrlScanRequest request) {
        return ResponseEntity.ok(scanService.analyzeUrl(auth.getName(), request));
    }

    @GetMapping("/history")
    public ResponseEntity<List<ScanResultResponse>> getHistory(Authentication auth,
                                                                 @RequestParam(required = false) RiskLevel riskLevel,
                                                                 @RequestParam(required = false) MessageType messageType,
                                                                 @RequestParam(required = false) String scamType,
                                                                 @RequestParam(required = false) String search,
                                                                 @RequestParam(defaultValue = "DATE") String sortBy,
                                                                 @RequestParam(defaultValue = "DESC") String direction) {
        if (!sortBy.equalsIgnoreCase("DATE") && !sortBy.equalsIgnoreCase("RISK")) {
            throw new BadRequestException("sortBy must be DATE or RISK");
        }
        if (!direction.equalsIgnoreCase("ASC") && !direction.equalsIgnoreCase("DESC")) {
            throw new BadRequestException("direction must be ASC or DESC");
        }
        return ResponseEntity.ok(scanService.getHistory(auth.getName(), riskLevel, messageType,
                scamType, search, sortBy, direction.equalsIgnoreCase("ASC")));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ScanResultResponse> getScan(Authentication auth, @PathVariable Long id) {
        return ResponseEntity.ok(scanService.getScanById(auth.getName(), id));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteScan(Authentication auth, @PathVariable Long id) {
        scanService.deleteScan(auth.getName(), id);
        return ResponseEntity.noContent().build();
    }
}
