# AI ScamShield – Intelligent Scam Message Detection System

A full-stack, software-only (no hardware/IoT) college project that analyzes SMS,
WhatsApp, and Email messages, as well as suspicious URLs, to detect and explain
potential scams using a structured AI/NLP analysis engine.

---

## 1. Project Description

AI ScamShield lets a user paste in a message or a URL and get back:
- A classification: **SAFE**, **SUSPICIOUS**, or **LIKELY SCAM**
- A risk score from 0–100
- A list of detected indicators (why it was flagged)
- A plain-language explanation
- A recommended action

Every analysis is stored in the user's history, aggregated into a personal
dashboard, and rolled up into an admin dashboard for the whole system. Users
can also give feedback ("this was actually a scam" / "this was safe") on
each result, which is stored for future model improvement.

The system never claims certainty — it always uses cautious language such as
"likely scam" or "suspicious," and never accuses a specific person of a crime.

---

## 2. Features

- **Authentication:** register, login, logout (JWT), BCrypt password hashing, USER/ADMIN roles
- **Message Scanner:** SMS / WhatsApp / Email analysis with sender info
- **URL Scanner:** structural phishing/scam analysis (no crawling)
- **AI Explanation:** human-readable "why is this suspicious?" reasoning
- **Evidence confidence and scam category:** deterministic confidence derived
  from matched indicator count and weights, and a category derived from those
  indicators (confidence is not a calibrated probability)
- **ScamShield Assistant:** answers questions from a fresh analysis or a saved
  scan, using the same evidence and recommendation
- **Detection History:** view, search, filter by risk level, delete
- **Personal Dashboard:** totals, breakdown by risk level and scam type, seven-day
  risk trend, top indicators, high-risk scans, and recent analysis
- **Admin Dashboard:** user management (enable/disable), system-wide statistics
- **Feedback System:** confirm/deny scam classifications, stored for future model training
- **Modular AI layer:** real LLM provider integration (optional) with automatic,
  fully offline fallback to a structured rule-based NLP engine — the project
  always runs, with or without an API key

---

## 3. Architecture

```
Frontend (HTML/CSS/JS)  --->  REST API (Spring Boot)  --->  MySQL
                                     |
                                     v
                        ScamDetectionOrchestrator
                             /              \
                AiScamDetectionService   FallbackScamDetectionService
                (LLM provider, optional)  (offline rule-based NLP engine)
```

Backend package structure:

```
com.scamshield
├── controller/     REST endpoints
├── service/        business logic (Auth, Scan, Feedback, Admin)
│   └── ai/         ScamDetectionService interface + AI/Fallback implementations
├── repository/     Spring Data JPA repositories
├── entity/         JPA entities (User, Role, Scan, ScanIndicator, Feedback)
├── dto/            request/response objects
├── security/       JWT filter, util, UserDetails, CustomUserDetailsService
├── exception/      custom exceptions + global exception handler
├── config/         SecurityConfig, DataSeeder
└── util/           (reserved for shared helpers)
```

The AI layer is intentionally decoupled behind the `ScamDetectionService`
interface with two implementations (`AiScamDetectionService` and
`FallbackScamDetectionService`), selected automatically at runtime by
`ScamDetectionOrchestrator`. This means a different LLM provider/model can be
plugged in later just by implementing `AiProviderClient` again — no other
code needs to change.

---

## 4. Technology Stack

**Backend:** Java 17, Spring Boot 3.2, Spring Web, Spring Data JPA, Spring
Security, JWT (jjwt), Maven

**Database:** MySQL 8

**Frontend:** HTML5, CSS3, vanilla JavaScript (no framework/build step required)

**AI:** Modular provider interface — real LLM integration (Anthropic Messages
API by default, swappable) when an API key is configured, otherwise a fully
offline, structured multi-category regex/NLP scam-pattern analysis engine

---

## 5. AI Approach

### Local Fallback Engine (`FallbackScamDetectionService`) — always available
- Multi-category weighted pattern analysis: urgency/pressure, financial
  requests, credential/OTP harvesting, fake rewards, fake job offers,
  impersonation, personal-information requests, and link/URL structure
- Each matched pattern contributes a weight; weights are summed and capped
  at 100 to produce the risk score
- Classification thresholds: `< 25` → SAFE, `25–59` → SUSPICIOUS, `>= 60` → LIKELY SCAM
- URL analysis checks: HTTPS usage, IP-literal hosts, excessive subdomains,
  URL shorteners, suspicious keywords, hyphen-heavy domains, percent-encoding,
  `@`-symbol tricks, and overall length
- Explanations and recommendations are generated dynamically from whichever
  indicators actually fired — not static canned text

### LLM Provider Engine (`AiScamDetectionService`) — optional
- Used automatically when `AI_PROVIDER_ENABLED=true` and a valid
  `AI_PROVIDER_API_KEY` is set
- Sends a structured prompt instructing the model to return strict JSON
  matching the same result schema as the fallback engine
- If the API call fails, times out, or returns unparseable output, the
  orchestrator automatically and transparently falls back to the local
  engine — the user experience is never interrupted
- Every stored scan records which engine (`AI_LLM` or `FALLBACK_NLP`)
  produced it, for transparency

---

## 6. Database Setup

### Option A — Let Hibernate create it automatically (default)
Nothing to do for local development. `application.properties` defaults to a
file-backed H2 database and `spring.jpa.hibernate.ddl-auto=update`, so tables
are created/updated automatically. Set `DB_URL`, `DB_USERNAME`,
`DB_PASSWORD`, and `DB_DRIVER_CLASS_NAME` to use MySQL instead.

### Option B — Run the SQL script manually
```bash
mysql -u root -p < database/DATABASE_SETUP.sql
```

No accounts or passwords are seeded by default. Register a user through the
application. To provision an administrator on first startup, set
`SEED_ADMIN_USERNAME`, `SEED_ADMIN_EMAIL`, and `SEED_ADMIN_PASSWORD` in the
backend environment before starting the application. Set a unique
`JWT_SECRET` of at least 32 random characters; the backend intentionally has
no built-in signing secret.

---

## 7. MySQL Configuration

Copy `backend/.env.example` to `backend/.env` and replace the placeholder JWT
secret with a unique random value of at least 32 characters. Spring Boot
imports this file automatically. Configure optional administrator values only
when needed:

```
DB_NAME=scamshield_db
DB_USERNAME=root
DB_PASSWORD=your_mysql_password
JWT_SECRET=your_unique_random_secret_of_at_least_32_characters
```

---

## 8. AI API Configuration (optional)

```
AI_PROVIDER_ENABLED=false      # set true to use a real LLM
AI_PROVIDER_API_KEY=           # leave blank to always use the offline engine
AI_PROVIDER_URL=https://api.anthropic.com/v1/messages
AI_PROVIDER_MODEL=claude-sonnet-4-6
AI_PROVIDER_TIMEOUT_MS=8000
```

The project is fully functional with `AI_PROVIDER_ENABLED=false` — this is
the default and requires no API key. The offline engine uses weighted,
deterministic NLP rules. Optional category weight multipliers can be set with
`SCAM_WEIGHT_URGENCY`, `SCAM_WEIGHT_FINANCIAL`, `SCAM_WEIGHT_CREDENTIAL`,
`SCAM_WEIGHT_REWARD`, `SCAM_WEIGHT_JOB`, `SCAM_WEIGHT_IMPERSONATION`,
`SCAM_WEIGHT_PERSONAL_INFORMATION`, `SCAM_WEIGHT_LINK`, `SCAM_WEIGHT_URL`,
`SCAM_WEIGHT_SENDER`, and `SCAM_WEIGHT_STYLE`.

---

## 9. How to Run — Backend

**Prerequisites:** Java 17+, Maven, MySQL running locally.

```bash
cd backend
cp .env.example .env      # set a unique JWT_SECRET; add DB/admin settings as needed
mvn spring-boot:run
```

Or open `backend` as a Maven project in IntelliJ IDEA / VS Code and run
`ScamShieldApplication.java` directly (set the environment variables in your
run configuration).

The API starts on `http://localhost:8080`.

---

## 10. How to Run — Frontend

The frontend is static HTML/CSS/JS — no build step required.

```bash
cd frontend
# Any static file server works, e.g.:
npx serve .
# or simply open frontend/login.html directly in a browser
```

If you serve the frontend from an origin other than
`http://localhost:5500` / `http://127.0.0.1:5500` / `http://localhost:3000`,
add your origin to `CORS_ALLOWED_ORIGINS` in the backend configuration.

The API base URL is configured at the top of `frontend/js/api.js`
(`API_BASE_URL`) — update it if your backend runs on a different host/port.

---

## 11. API Documentation

See [`docs/API_TESTING.md`](docs/API_TESTING.md) for full endpoint
documentation with example requests/responses and sample scam/safe messages
for testing.

Main endpoints:
```
POST   /api/auth/register
POST   /api/auth/login
POST   /api/scans/message
POST   /api/scans/url
GET    /api/scans/history?riskLevel=&messageType=&scamType=&search=&sortBy=&direction=
GET    /api/scans/{id}
DELETE /api/scans/{id}
POST   /api/feedback
GET    /api/dashboard
GET    /api/dashboard/stats
GET    /api/dashboard/trends
GET    /api/dashboard/scam-types
POST   /api/assistant/analyze
GET    /api/admin/statistics
GET    /api/admin/users
PUT    /api/admin/users/{id}/status
```

---

## 12. Account Setup

Create a normal account using the registration page. If the demo needs an
administrator, configure the optional `SEED_ADMIN_*` environment variables
before the first backend startup. Do not use shared or production passwords
for a classroom demonstration.

---

## 13. Screenshots

_Add screenshots here after running the project locally:_
- `docs/screenshots/login.png`
- `docs/screenshots/dashboard.png`
- `docs/screenshots/scanner-result.png`
- `docs/screenshots/admin.png`

---

## 14. Testing

Backend tests live under `backend/src/test/java/com/scamshield/`:
- `service/FallbackScamDetectionServiceTest.java` — unit tests for the
  offline NLP engine (safe message, scam message, OTP detection, URL risk
  comparison)
- `controller/AuthControllerTest.java` — integration tests for
  register/login flows, validation errors, and bad-credential handling
  (runs against an in-memory H2 database via the `test` Spring profile)

Run all tests:
```bash
cd backend
mvn test
```

---

## 15. Future Enhancements

- Real-time browser extension integration for inline scanning
- Feedback-driven model fine-tuning pipeline using the `feedback` table
- Multi-language scam pattern support
- Rate limiting per user/IP at the gateway level
- Email/SMS gateway integration for automatic inbound scanning
- Export scan history to PDF/CSV

---

## 16. Project Structure

```
AI-ScamShield/
├── backend/                  Spring Boot application
│   ├── src/main/java/com/scamshield/...
│   ├── src/test/java/com/scamshield/...
│   ├── pom.xml
│   ├── .env.example
│   └── README.md
├── frontend/                 Static HTML/CSS/JS client
│   ├── index.html, login.html, register.html, dashboard.html,
│   │   scanner.html, url-scanner.html, history.html, profile.html, admin.html
│   ├── css/styles.css
│   └── js/api.js
├── database/
│   └── DATABASE_SETUP.sql
├── docs/
│   └── API_TESTING.md
├── README.md                 (this file)
└── .gitignore
```
