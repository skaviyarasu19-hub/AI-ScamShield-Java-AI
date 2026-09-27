package com.scamshield.service.ai;

import com.scamshield.entity.MessageType;
import com.scamshield.entity.RiskLevel;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * FallbackScamDetectionService
 * -----------------------------
 * A fully local, offline, structured scam-pattern analysis engine.
 *
 * This is NOT a simple "contains keyword X -> flag" checker. It performs:
 *   1. Multi-category linguistic pattern matching (regex-based NLP heuristics)
 *      across urgency/pressure, financial requests, credential harvesting,
 *      fake rewards, impersonation, social engineering and more.
 *   2. Weighted scoring per category, combined and normalized into a 0-100
 *      risk score (categories can compound, but score is capped at 100).
 *   3. Structural heuristics for URLs (IP-literal hosts, punycode/homograph
 *      hints, excessive subdomains, suspicious TLD/keyword combinations,
 *      URL shorteners, HTTPS absence, encoded characters, length).
 *   4. Human-readable, non-accusatory explanations generated from whichever
 *      indicators actually fired, rather than a static canned message.
 *
 * This engine is used automatically whenever no AI provider API key is
 * configured, or when the AI provider call fails (see
 * ScamDetectionOrchestrator), so the project is always fully runnable.
 */
@Service
@RequiredArgsConstructor
public class FallbackScamDetectionService implements ScamDetectionService {

    private final ScamAnalysisProperties analysisProperties;

    @Override
    public String engineName() {
        return "FALLBACK_NLP";
    }

    // =========================================================================================
    // MESSAGE ANALYSIS
    // =========================================================================================

    private record Rule(String code, String description, int weight, Pattern pattern) {
    }

    // Category: Urgency & pressure tactics
    private static final List<Rule> URGENCY_RULES = List.of(
            new Rule("URGENCY_TIME_PRESSURE", "Creates a false sense of urgency or a ticking deadline",
                    12, Pattern.compile("\\b(urgent|immediately|right away|act now|expires? (today|soon|in \\d+)|within \\d+\\s*(hours?|minutes?|days?)|last chance|final (notice|warning)|time[- ]sensitive)\\b", Pattern.CASE_INSENSITIVE)),
            new Rule("URGENCY_ACCOUNT_THREAT", "Threatens account suspension, closure, or legal action if no action is taken",
                    16, Pattern.compile("\\b(account (will be|has been) (suspended|blocked|locked|closed|terminated)|suspend(ed)? your account|legal action|failure to (respond|comply)|penalty|fine of)\\b", Pattern.CASE_INSENSITIVE))
    );

    // Category: Financial requests
    private static final List<Rule> FINANCIAL_RULES = List.of(
            new Rule("FIN_UPFRONT_PAYMENT", "Requests an upfront payment, processing fee, or advance transfer",
                    18, Pattern.compile("\\b(processing fee|upfront (payment|fee)|advance (fee|payment)|pay (a\\s+)?(small\\s+)?fee|courier (fee|charge)|customs (fee|duty)|clearance fee|registration fee|send money|wire transfer|western union|money ?gram|gift cards?|crypto(currency)?\\s*(wallet|payment)|bitcoin|usdt)\\b", Pattern.CASE_INSENSITIVE)),
            new Rule("FIN_BANK_DETAILS", "Asks the recipient to share bank account or card details",
                    17, Pattern.compile("\\b(bank account (number|details)|card number|cvv|ifsc|routing number|account number and (ifsc|routing))\\b", Pattern.CASE_INSENSITIVE)),
            new Rule("FIN_INVESTMENT_SCHEME", "References guaranteed high returns or investment schemes typical of financial scams",
                    15, Pattern.compile("\\b(guaranteed returns?|double your (money|investment)|risk[- ]free investment|forex trading opportunity|investment opportunity.*(guarantee|profit))\\b", Pattern.CASE_INSENSITIVE))
    );

    // Category: Credential / OTP harvesting
    private static final List<Rule> CREDENTIAL_RULES = List.of(
            new Rule("CRED_OTP_REQUEST", "Requests an OTP, PIN, password, or verification code",
                    20, Pattern.compile("\\b(otp|one[- ]time password|pin code|verification code|share (your )?(otp|pin|password|code)|enter your (otp|pin|password))\\b", Pattern.CASE_INSENSITIVE)),
            new Rule("CRED_LOGIN_UPDATE", "Asks the user to 'verify', 'update' or 're-confirm' login/account details via a link",
                    14, Pattern.compile("\\b(verify your account|update your (details|information|kyc)|confirm your (identity|account|details)|re-?activate your account|click (here|below) to (verify|login|update))\\b", Pattern.CASE_INSENSITIVE))
    );

    // Category: Fake rewards / prizes
    private static final List<Rule> REWARD_RULES = List.of(
            new Rule("REWARD_PRIZE_WIN", "Claims the recipient has won a prize, lottery, or reward",
                    17, Pattern.compile("\\b(you('| ha)ve won|congratulations.*(won|selected|winner)|lucky (draw|winner)|lottery|jackpot|claim your (prize|reward|gift)|free (gift|iphone|voucher|reward))\\b", Pattern.CASE_INSENSITIVE)),
            new Rule("REWARD_CASHBACK", "Offers an unusually large or unsolicited cashback / refund",
                    10, Pattern.compile("\\b(cashback of|refund of ₹?\\$?\\d|you are eligible for a refund)\\b", Pattern.CASE_INSENSITIVE))
    );

    // Category: Fake job / employment scams
    private static final List<Rule> JOB_RULES = List.of(
            new Rule("JOB_OFFER_TOO_GOOD", "Offers a job with unusually high pay for minimal work, often requiring an upfront fee",
                    14, Pattern.compile("\\b(work from home.*(earn|salary)|earn ₹?\\$?\\d+.*per (day|hour|week)|part[- ]time job.*earn|no experience needed.*earn|registration fee.*job|job offer.*(deposit|fee))\\b", Pattern.CASE_INSENSITIVE))
    );

    // Category: Impersonation
    private static final List<Rule> IMPERSONATION_RULES = List.of(
            new Rule("IMPERSONATION_AUTHORITY", "Impersonates a bank, government body, courier, or well-known company",
                    12, Pattern.compile("\\b(this is (from )?(income tax|irs|customs|police|bank of|amazon|paypal|microsoft|apple support|fedex|ups|dhl)\\b|official notice from|on behalf of (the )?government)", Pattern.CASE_INSENSITIVE)),
            new Rule("IMPERSONATION_FAMILY", "Impersonates a relative or acquaintance in urgent distress (common in social engineering scams)",
                    13, Pattern.compile("\\b(it'?s me,? (mom|dad|son|daughter)|i lost my phone.*this is my new number|i'?m in trouble.*send money)\\b", Pattern.CASE_INSENSITIVE))
    );

    // Category: Personal information harvesting
    private static final List<Rule> PII_RULES = List.of(
            new Rule("PII_REQUEST", "Requests sensitive personal information (ID numbers, date of birth, address, etc.)",
                    11, Pattern.compile("\\b(aadhaar|social security number|ssn|passport number|date of birth and|full name and address|share your (id|identity) proof)\\b", Pattern.CASE_INSENSITIVE))
    );

    // Category: Suspicious link presence (checked separately from full URL analysis)
    private static final Pattern URL_PATTERN = Pattern.compile("\\bhttps?://[\\w\\-.:/%?=&#]+|\\bwww\\.[\\w\\-.:/%?=&#]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern SHORTENER_PATTERN = Pattern.compile("\\b(bit\\.ly|tinyurl\\.com|t\\.co|goo\\.gl|is\\.gd|ow\\.ly|shorte\\.st|cutt\\.ly)\\b", Pattern.CASE_INSENSITIVE);

    private static final List<List<Rule>> ALL_MESSAGE_CATEGORIES = List.of(
            URGENCY_RULES, FINANCIAL_RULES, CREDENTIAL_RULES, REWARD_RULES, JOB_RULES, IMPERSONATION_RULES, PII_RULES
    );

    @Override
    public ScamAnalysisResult analyzeMessage(String content, String senderInfo, MessageType messageType) {
        String text = content == null ? "" : content;
        String combinedText = text + " " + (senderInfo == null ? "" : senderInfo);

        List<ScamAnalysisResult.Indicator> fired = new ArrayList<>();
        for (List<Rule> category : ALL_MESSAGE_CATEGORIES) {
            for (Rule rule : category) {
                Matcher m = rule.pattern().matcher(combinedText);
                if (m.find()) {
                    fired.add(ScamAnalysisResult.Indicator.builder()
                            .code(rule.code())
                            .description(rule.description())
                            .weight(weightFor(rule.code(), rule.weight()))
                            .build());
                }
            }
        }

        // Suspicious link contained in the message body
        Matcher urlMatcher = URL_PATTERN.matcher(text);
        if (urlMatcher.find()) {
            String foundUrl = urlMatcher.group();
            ScamAnalysisResult urlSubResult = analyzeUrl(foundUrl);
            if (urlSubResult.getRiskScore() >= 40) {
                fired.add(ScamAnalysisResult.Indicator.builder()
                        .code("LINK_SUSPICIOUS")
                        .description("Contains a suspicious link with risky structural characteristics")
                        .weight(weightFor("LINK_SUSPICIOUS", 15))
                        .build());
            } else {
                fired.add(ScamAnalysisResult.Indicator.builder()
                        .code("LINK_PRESENT")
                        .description("Contains a link that should be verified independently before opening")
                        .weight(weightFor("LINK_PRESENT", 6))
                        .build());
            }
        }

        // Sender-info heuristics: mismatched / spoofed-looking sender IDs
        if (senderInfo != null && senderInfo.matches(".*\\d{6,}.*") && messageType == MessageType.SMS) {
            fired.add(ScamAnalysisResult.Indicator.builder()
                    .code("SENDER_SUSPICIOUS_ID")
                    .description("Sender ID looks like a randomized number rather than a registered business ID")
                    .weight(weightFor("SENDER_SUSPICIOUS_ID", 8))
                    .build());
        }

        // ALL-CAPS / excessive punctuation heuristic (mild signal)
        long exclamations = text.chars().filter(c -> c == '!').count();
        if (exclamations >= 3) {
            fired.add(ScamAnalysisResult.Indicator.builder()
                    .code("STYLE_EXCESSIVE_PUNCTUATION")
                    .description("Uses excessive exclamation marks, a common pressure/excitement tactic")
                    .weight(weightFor("STYLE_EXCESSIVE_PUNCTUATION", 4))
                    .build());
        }

        int riskScore = Math.min(100, fired.stream().mapToInt(ScamAnalysisResult.Indicator::getWeight).sum());
        RiskLevel classification = classify(riskScore);

        String explanation = buildExplanation(fired, classification);
        String recommendation = buildRecommendation(classification);

        return ScamAnalysisResult.builder()
                .classification(classification)
                .riskScore(riskScore)
                .indicators(fired)
                .explanation(explanation)
                .recommendation(recommendation)
                .build();
    }

    // =========================================================================================
    // URL ANALYSIS
    // =========================================================================================

    private static final Pattern IP_HOST_PATTERN = Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$");
    private static final Pattern SUSPICIOUS_KEYWORDS_IN_URL = Pattern.compile(
            "(secure[-]?login|verify[-]?account|update[-]?billing|confirm[-]?identity|account[-]?suspended|banking[-]?alert|reward[-]?claim|prize[-]?claim|free[-]?gift)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SUSPICIOUS_QUERY_PARAMETER = Pattern.compile(
            "(^|&)(redirect|redirect_url|return|return_url|continue|next|token|session|verify|payment)=",
            Pattern.CASE_INSENSITIVE);

    @Override
    public ScamAnalysisResult analyzeUrl(String rawUrl) {
        List<ScamAnalysisResult.Indicator> fired = new ArrayList<>();
        String normalized = rawUrl.trim();
        if (!normalized.matches("^[a-zA-Z]+://.*")) {
            normalized = "http://" + normalized; // allow parsing bare domains
        }

        URI uri;
        String host;
        String path;
        String query;
        String scheme;
        try {
            uri = new URI(normalized);
            host = uri.getHost() == null ? "" : uri.getHost();
            path = uri.getPath() == null ? "" : uri.getPath();
            query = uri.getRawQuery() == null ? "" : uri.getRawQuery();
            scheme = uri.getScheme() == null ? "" : uri.getScheme();
        } catch (URISyntaxException e) {
            int malformedScore = weightFor("URL_MALFORMED", 20);
            fired.add(ScamAnalysisResult.Indicator.builder()
                    .code("URL_MALFORMED")
                    .description("URL is malformed or contains invalid characters, often used to confuse filters")
                    .weight(malformedScore)
                    .build());
            return ScamAnalysisResult.builder()
                    .classification(classify(malformedScore))
                    .riskScore(Math.min(100, malformedScore))
                    .indicators(fired)
                    .explanation("The submitted URL could not be parsed correctly, which is itself a common trait of obfuscated phishing links.")
                    .recommendation("Do not open this link. Verify the destination through an official source instead.")
                    .build();
        }

        // HTTPS check
        if (!"https".equalsIgnoreCase(scheme)) {
            fired.add(ScamAnalysisResult.Indicator.builder()
                    .code("URL_NO_HTTPS")
                    .description("Does not use HTTPS encryption")
                    .weight(weightFor("URL_NO_HTTPS", 10))
                    .build());
        }

        // IP literal host
        if (IP_HOST_PATTERN.matcher(host).matches()) {
            fired.add(ScamAnalysisResult.Indicator.builder()
                    .code("URL_IP_HOST")
                    .description("Uses a raw IP address instead of a domain name")
                    .weight(weightFor("URL_IP_HOST", 22))
                    .build());
        }

        // Excessive subdomains
        int dotCount = host.isEmpty() ? 0 : (int) host.chars().filter(c -> c == '.').count();
        if (dotCount >= 3) {
            fired.add(ScamAnalysisResult.Indicator.builder()
                    .code("URL_EXCESSIVE_SUBDOMAINS")
                    .description("Contains an unusually large number of subdomains, often used to disguise the real domain")
                    .weight(weightFor("URL_EXCESSIVE_SUBDOMAINS", 15))
                    .build());
        }

        // URL shortener
        if (SHORTENER_PATTERN.matcher(host).find()) {
            fired.add(ScamAnalysisResult.Indicator.builder()
                    .code("URL_SHORTENER")
                    .description("Uses a URL shortening service, which can hide the true destination")
                    .weight(weightFor("URL_SHORTENER", 12))
                    .build());
        }

        // Suspicious keywords in domain/path
        if (SUSPICIOUS_KEYWORDS_IN_URL.matcher(host + path + query).find()) {
            fired.add(ScamAnalysisResult.Indicator.builder()
                    .code("URL_SUSPICIOUS_KEYWORDS")
                    .description("Domain or path contains phishing-style keywords (e.g. 'secure-login', 'verify-account')")
                    .weight(weightFor("URL_SUSPICIOUS_KEYWORDS", 16))
                    .build());
        }

        if (host.toLowerCase().contains("xn--")) {
            fired.add(ScamAnalysisResult.Indicator.builder()
                    .code("URL_PUNYCODE_HOST")
                    .description("Domain uses punycode encoding, which can represent visually confusing internationalized names")
                    .weight(weightFor("URL_PUNYCODE_HOST", 12))
                    .build());
        }

        if (SUSPICIOUS_QUERY_PARAMETER.matcher(query).find()) {
            fired.add(ScamAnalysisResult.Indicator.builder()
                    .code("URL_SUSPICIOUS_QUERY")
                    .description("Query contains redirect, verification, payment, or session-style parameters that merit extra scrutiny")
                    .weight(weightFor("URL_SUSPICIOUS_QUERY", 10))
                    .build());
        }

        long specialCharacterCount = normalized.chars()
                .filter(c -> "?&=%@#".indexOf(c) >= 0)
                .count();
        if (specialCharacterCount > 12) {
            fired.add(ScamAnalysisResult.Indicator.builder()
                    .code("URL_EXCESSIVE_SPECIAL_CHARS")
                    .description("Contains an unusually high number of URL control characters that may obscure the destination")
                    .weight(weightFor("URL_EXCESSIVE_SPECIAL_CHARS", 8))
                    .build());
        }

        // Hyphen-heavy host (common in typosquatting/phishing kits)
        long hyphenCount = host.chars().filter(c -> c == '-').count();
        if (hyphenCount >= 2) {
            fired.add(ScamAnalysisResult.Indicator.builder()
                    .code("URL_HYPHEN_HEAVY")
                    .description("Domain name contains multiple hyphens, a pattern often seen in look-alike domains")
                    .weight(weightFor("URL_HYPHEN_HEAVY", 9))
                    .build());
        }

        // Encoded characters (percent-encoding used to obscure content)
        if (normalized.contains("%") && normalized.chars().filter(c -> c == '%').count() >= 2) {
            fired.add(ScamAnalysisResult.Indicator.builder()
                    .code("URL_ENCODED_CHARS")
                    .description("Contains multiple percent-encoded characters, which can be used to obscure the real URL")
                    .weight(weightFor("URL_ENCODED_CHARS", 8))
                    .build());
        }

        // Overall length
        if (normalized.length() > 100) {
            fired.add(ScamAnalysisResult.Indicator.builder()
                    .code("URL_EXCESSIVE_LENGTH")
                    .description("Unusually long URL, a pattern sometimes used to bury a malicious domain")
                    .weight(weightFor("URL_EXCESSIVE_LENGTH", 7))
                    .build());
        }

        // "@" trick (everything before @ is ignored by browsers -> phishing trick)
        if (normalized.contains("@")) {
            fired.add(ScamAnalysisResult.Indicator.builder()
                    .code("URL_AT_SYMBOL_TRICK")
                    .description("Contains an '@' symbol, a known technique to disguise the true destination domain")
                    .weight(weightFor("URL_AT_SYMBOL_TRICK", 18))
                    .build());
        }

        int riskScore = Math.min(100, fired.stream().mapToInt(ScamAnalysisResult.Indicator::getWeight).sum());
        RiskLevel classification = classify(riskScore);

        String explanation = fired.isEmpty()
                ? "No significant structural red flags were detected in this URL. It appears to follow standard, well-formed conventions."
                : buildExplanation(fired, classification);

        String recommendation = buildUrlRecommendation(classification);

        return ScamAnalysisResult.builder()
                .classification(classification)
                .riskScore(riskScore)
                .indicators(fired)
                .explanation(explanation)
                .recommendation(recommendation)
                .build();
    }

    // =========================================================================================
    // SHARED HELPERS
    // =========================================================================================

    private RiskLevel classify(int score) {
        if (score > analysisProperties.getSuspiciousMaxRisk()) return RiskLevel.LIKELY_SCAM;
        if (score > analysisProperties.getSafeMaxRisk()) return RiskLevel.SUSPICIOUS;
        return RiskLevel.SAFE;
    }

    private int weightFor(String code, int baseWeight) {
        ScamAnalysisProperties.Weights weights = analysisProperties.getWeights();
        String category = code.startsWith("URGENCY_") ? "urgency"
                : code.startsWith("FIN_") ? "financial"
                : code.startsWith("CRED_") ? "credential"
                : code.startsWith("REWARD_") ? "reward"
                : code.startsWith("JOB_") ? "job"
                : code.startsWith("IMPERSONATION_") ? "impersonation"
                : code.startsWith("PII_") ? "personalInformation"
                : code.startsWith("LINK_") ? "link"
                : code.startsWith("URL_") ? "url"
                : code.startsWith("SENDER_") ? "sender"
                : code.startsWith("STYLE_") ? "style" : null;

        double multiplier = category == null ? 1.0 : switch (category) {
            case "urgency" -> weights.getUrgency();
            case "financial" -> weights.getFinancial();
            case "credential" -> weights.getCredential();
            case "reward" -> weights.getReward();
            case "job" -> weights.getJob();
            case "impersonation" -> weights.getImpersonation();
            case "personalInformation" -> weights.getPersonalInformation();
            case "link" -> weights.getLink();
            case "url" -> weights.getUrl();
            case "sender" -> weights.getSender();
            case "style" -> weights.getStyle();
            default -> 1.0;
        };
        return Math.max(0, (int) Math.round(baseWeight * Math.max(0.0, multiplier)));
    }

    private String buildExplanation(List<ScamAnalysisResult.Indicator> fired, RiskLevel classification) {
        if (fired.isEmpty()) {
            return "No significant scam indicators were detected. The content appears to follow normal, non-manipulative language patterns.";
        }

        StringBuilder sb = new StringBuilder();
        switch (classification) {
            case LIKELY_SCAM -> sb.append("This content shows multiple strong indicators commonly associated with scams:\n");
            case SUSPICIOUS -> sb.append("This content shows some characteristics that warrant caution:\n");
            default -> sb.append("A small number of minor signals were noted:\n");
        }

        // De-duplicate by code while preserving order, cap explanation length
        Map<String, String> seen = new LinkedHashMap<>();
        for (ScamAnalysisResult.Indicator ind : fired) {
            seen.putIfAbsent(ind.getCode(), ind.getDescription());
        }
        int count = 0;
        for (String desc : seen.values()) {
            sb.append("- ").append(desc).append("\n");
            count++;
            if (count >= 8) break; // keep explanation readable
        }
        return sb.toString().trim();
    }

    private String buildRecommendation(RiskLevel classification) {
        return switch (classification) {
            case LIKELY_SCAM -> "Do not click any links, reply, share personal information, or send money. "
                    + "Verify the sender through an official, independently-looked-up channel before taking any action. "
                    + "Consider blocking and reporting the sender.";
            case SUSPICIOUS -> "Treat this message with caution. Do not act on it immediately — independently verify "
                    + "the sender's identity through official channels before sharing any information or making a payment.";
            case SAFE -> "No immediate red flags were found. As a general practice, remain cautious with unsolicited "
                    + "messages requesting personal or financial information.";
        };
    }

    private String buildUrlRecommendation(RiskLevel classification) {
        return switch (classification) {
            case LIKELY_SCAM -> "Avoid visiting this URL. It exhibits multiple characteristics commonly seen in phishing "
                    + "or scam websites. Verify the organization's real website by typing the official domain directly into your browser.";
            case SUSPICIOUS -> "Exercise caution with this URL. Verify its legitimacy independently before entering any "
                    + "credentials or personal information.";
            case SAFE -> "No major structural red flags were found in this URL. Still, always verify unfamiliar links "
                    + "before entering sensitive information.";
        };
    }
}
