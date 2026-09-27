# API Testing Guide - AI ScamShield

Base URL (local): `http://localhost:8080/api`

All requests/responses are JSON. Protected endpoints require:
```
Authorization: Bearer <jwt-token>
```

---

## 1. Register

```
POST /api/auth/register
Content-Type: application/json

{
  "username": "johndoe",
  "email": "johndoe@example.com",
  "password": "SecurePass123"
}
```

**Response 201:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "userId": 3,
  "username": "johndoe",
  "roles": ["ROLE_USER"]
}
```

---

## 2. Login

```
POST /api/auth/login
Content-Type: application/json

{
  "username": "johndoe",
  "password": "SecurePass123"
}
```

**Response 200:** same shape as register.

Seeded demo accounts (created automatically on first backend startup):
- `admin` / `Admin@123` (ROLE_ADMIN + ROLE_USER)
- `testuser` / `Test@123` (ROLE_USER)

---

## 3. Analyze a Message

```
POST /api/scans/message
Authorization: Bearer <token>
Content-Type: application/json

{
  "content": "Congratulations! You have won a lottery of $1,000,000!!! Pay a small processing fee immediately to claim your prize before it expires today. Send your bank account number and OTP now.",
  "senderInfo": "LOTTERY-WIN",
  "messageType": "SMS"
}
```

**Response 200:**
```json
{
  "id": 12,
  "messageType": "SMS",
  "content": "Congratulations! You have won...",
  "classification": "LIKELY_SCAM",
  "riskScore": 91,
  "riskLevelLabel": "Likely Scam",
  "indicators": [
    { "code": "REWARD_PRIZE_WIN", "description": "Claims the recipient has won a prize, lottery, or reward", "weight": 17 },
    { "code": "FIN_UPFRONT_PAYMENT", "description": "Requests an upfront payment, processing fee, or advance transfer", "weight": 18 },
    { "code": "CRED_OTP_REQUEST", "description": "Requests an OTP, PIN, password, or verification code", "weight": 20 }
  ],
  "explanation": "This content shows multiple strong indicators commonly associated with scams:\n- Claims the recipient has won a prize...\n- Requests an upfront payment...",
  "recommendation": "Do not click any links, reply, share personal information, or send money...",
  "analysisEngine": "FALLBACK_NLP",
  "createdAt": "2026-09-27T10:15:00"
}
```

`messageType` must be one of: `SMS`, `WHATSAPP`, `EMAIL`.

---

## 4. Analyze a URL

```
POST /api/scans/url
Authorization: Bearer <token>
Content-Type: application/json

{
  "url": "http://192.168.10.5/secure-login/verify-account"
}
```

**Response 200:** same shape as message analysis (with `messageType: "URL"`).

---

## 5. Get Scan History

```
GET /api/scans/history
GET /api/scans/history?riskLevel=LIKELY_SCAM
Authorization: Bearer <token>
```

**Response 200:** array of scan result objects (newest first).

---

## 6. Get a Single Scan

```
GET /api/scans/{id}
Authorization: Bearer <token>
```

---

## 7. Delete a Scan

```
DELETE /api/scans/{id}
Authorization: Bearer <token>
```

**Response:** 204 No Content

---

## 8. Submit Feedback

```
POST /api/feedback
Authorization: Bearer <token>
Content-Type: application/json

{
  "scanId": 12,
  "confirmedScam": true,
  "comment": "Received a call about this too, confirmed scam."
}
```

**Response:** 200 OK

---

## 9. Dashboard Stats

```
GET /api/dashboard
Authorization: Bearer <token>
```

**Response 200:**
```json
{
  "totalScans": 14,
  "safeCount": 6,
  "suspiciousCount": 5,
  "likelyScamCount": 3,
  "averageRiskScore": 38.21,
  "recentScans": [ ... last 5 scans ... ]
}
```

---

## 10. Admin: Statistics (ROLE_ADMIN only)

```
GET /api/admin/statistics
Authorization: Bearer <admin-token>
```

**Response 200:**
```json
{
  "totalUsers": 5,
  "activeUsers": 4,
  "totalScans": 42,
  "safeCount": 20,
  "suspiciousCount": 15,
  "likelyScamCount": 7
}
```

---

## 11. Admin: List Users (ROLE_ADMIN only)

```
GET /api/admin/users
Authorization: Bearer <admin-token>
```

---

## 12. Admin: Enable / Disable a User (ROLE_ADMIN only)

```
PUT /api/admin/users/{id}/status
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "enabled": false
}
```

---

## Sample cURL commands

```bash
# Register
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"johndoe","email":"johndoe@example.com","password":"SecurePass123"}'

# Login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"johndoe","password":"SecurePass123"}'

# Analyze a message (replace TOKEN)
curl -X POST http://localhost:8080/api/scans/message \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"content":"Your account will be suspended, share your OTP now!","senderInfo":"BANK-ALERT","messageType":"SMS"}'
```

## Sample scam messages for manual testing

See `frontend/js` demo data / this list — paste any of these into the Message Scanner:

1. **Fake lottery:** "Congratulations! You have won $500,000 in the international lottery. Send your bank details to claim your prize."
2. **Fake bank warning:** "URGENT: Your account will be suspended in 24 hours. Verify your account immediately by clicking here and entering your OTP."
3. **Fake job offer:** "Work from home and earn $500/day! No experience needed. Pay a small registration fee to get started today."
4. **Fake parcel delivery:** "Your parcel could not be delivered. Pay a customs clearance fee of $2.99 to reschedule delivery."
5. **Fake KYC update:** "Your KYC has expired. Update your details immediately or your account will be blocked."
6. **Fake OTP request:** "Your bank has detected suspicious activity. Share the OTP sent to your phone to secure your account."
7. **Fake investment offer:** "Double your money in 7 days! Guaranteed returns with zero risk. Invest now."
8. **Phishing link:** "Your Amazon account has an issue. Verify now: http://amaz0n-secure-login.verify-account.xyz"

## Sample safe messages

1. "Hey, are we still on for dinner tonight at 7?"
2. "Your OTP for login is 482910. Do not share this with anyone." *(Note: this one intentionally still triggers a mild CRED_OTP_REQUEST-adjacent signal-free path since it warns against sharing — legitimate bank OTP messages typically don't ask the user to send the OTP anywhere.)*
3. "Reminder: your dentist appointment is tomorrow at 10am."
4. "Thanks for the update, I'll review the document and get back to you by Friday."
