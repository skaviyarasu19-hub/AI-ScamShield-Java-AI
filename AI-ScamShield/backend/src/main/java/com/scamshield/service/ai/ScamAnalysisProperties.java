package com.scamshield.service.ai;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "scam.analysis")
public class ScamAnalysisProperties {

    private int safeMaxRisk = 24;
    private int suspiciousMaxRisk = 59;
    private final Weights weights = new Weights();

    public int getSafeMaxRisk() {
        return safeMaxRisk;
    }

    public void setSafeMaxRisk(int safeMaxRisk) {
        this.safeMaxRisk = safeMaxRisk;
    }

    public int getSuspiciousMaxRisk() {
        return suspiciousMaxRisk;
    }

    public void setSuspiciousMaxRisk(int suspiciousMaxRisk) {
        this.suspiciousMaxRisk = suspiciousMaxRisk;
    }

    public Weights getWeights() {
        return weights;
    }

    public static class Weights {
        private double urgency = 1.0;
        private double financial = 1.0;
        private double credential = 1.0;
        private double reward = 1.0;
        private double job = 1.0;
        private double impersonation = 1.0;
        private double personalInformation = 1.0;
        private double link = 1.0;
        private double url = 1.0;
        private double sender = 1.0;
        private double style = 1.0;

        public double getUrgency() { return urgency; }
        public void setUrgency(double urgency) { this.urgency = urgency; }
        public double getFinancial() { return financial; }
        public void setFinancial(double financial) { this.financial = financial; }
        public double getCredential() { return credential; }
        public void setCredential(double credential) { this.credential = credential; }
        public double getReward() { return reward; }
        public void setReward(double reward) { this.reward = reward; }
        public double getJob() { return job; }
        public void setJob(double job) { this.job = job; }
        public double getImpersonation() { return impersonation; }
        public void setImpersonation(double impersonation) { this.impersonation = impersonation; }
        public double getPersonalInformation() { return personalInformation; }
        public void setPersonalInformation(double personalInformation) { this.personalInformation = personalInformation; }
        public double getLink() { return link; }
        public void setLink(double link) { this.link = link; }
        public double getUrl() { return url; }
        public void setUrl(double url) { this.url = url; }
        public double getSender() { return sender; }
        public void setSender(double sender) { this.sender = sender; }
        public double getStyle() { return style; }
        public void setStyle(double style) { this.style = style; }
    }
}
