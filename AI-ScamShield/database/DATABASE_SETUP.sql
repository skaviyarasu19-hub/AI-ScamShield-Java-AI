-- =========================================================================
-- AI ScamShield - MySQL Database Setup Script
-- =========================================================================
-- This script is OPTIONAL: Spring Boot / Hibernate will auto-create the
-- database and tables on first run (spring.jpa.hibernate.ddl-auto=update
-- and createDatabaseIfNotExist=true in application.properties).
--
-- Use this script if you prefer to set up the schema manually, or want to
-- inspect the expected structure ahead of time.
-- =========================================================================

CREATE DATABASE IF NOT EXISTS scamshield_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE scamshield_db;

-- ---------------------------------------------------------------------
-- Roles
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(30) NOT NULL UNIQUE
);

INSERT IGNORE INTO roles (name) VALUES ('ROLE_USER');
INSERT IGNORE INTO roles (name) VALUES ('ROLE_ADMIN');

-- ---------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME NOT NULL
);

-- ---------------------------------------------------------------------
-- User <-> Role mapping (many-to-many)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_roles (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------
-- Scans
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scans (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    message_type VARCHAR(20) NOT NULL,       -- SMS, WHATSAPP, EMAIL, URL
    sender_info VARCHAR(150),
    content TEXT NOT NULL,
    classification VARCHAR(20) NOT NULL,     -- SAFE, SUSPICIOUS, LIKELY_SCAM
    risk_score INT NOT NULL,
    explanation TEXT,
    recommendation TEXT,
    analysis_engine VARCHAR(30) DEFAULT 'FALLBACK_NLP',
    created_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_scans_user_id ON scans(user_id);
CREATE INDEX idx_scans_classification ON scans(classification);

-- ---------------------------------------------------------------------
-- Scan Indicators (one scan can have many detected indicators)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_indicators (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id BIGINT NOT NULL,
    code VARCHAR(100) NOT NULL,
    description VARCHAR(255) NOT NULL,
    weight INT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX idx_scan_indicators_scan_id ON scan_indicators(scan_id);

-- ---------------------------------------------------------------------
-- Feedback
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS feedback (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    confirmed_scam BOOLEAN NOT NULL,
    comment VARCHAR(255),
    created_at DATETIME NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------
-- Optional administrator provisioning
-- ---------------------------------------------------------------------
-- No accounts are seeded by default. Set SEED_ADMIN_USERNAME,
-- SEED_ADMIN_EMAIL, and SEED_ADMIN_PASSWORD before first startup to create an
-- administrator with a BCrypt-hashed password through the Java application.
--
