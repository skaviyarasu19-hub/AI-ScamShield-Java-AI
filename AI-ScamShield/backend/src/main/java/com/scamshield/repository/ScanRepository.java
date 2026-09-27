package com.scamshield.repository;

import com.scamshield.entity.RiskLevel;
import com.scamshield.entity.Scan;
import com.scamshield.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ScanRepository extends JpaRepository<Scan, Long> {
    List<Scan> findByUserOrderByCreatedAtDesc(User user);
    List<Scan> findByUserAndClassificationOrderByCreatedAtDesc(User user, RiskLevel classification);
    long countByUser(User user);
    long countByUserAndClassification(User user, RiskLevel classification);
    long countByClassification(RiskLevel classification);
}
