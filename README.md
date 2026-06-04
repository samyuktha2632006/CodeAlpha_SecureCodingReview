# Secure Code Auditor - Backend

Node.js + Express + MongoDB REST API for detecting security vulnerabilities in source code.

## Setup

### 1. Install dependencies
```bash
cd server
npm install
```

### 2. Configure environment
```bash
cp .env.example .env
```
Edit `.env` and set your MongoDB URI.

### 3. Run the server
```bash
# Development (auto-restart)
npm run dev

# Production
npm start
```

Server runs at: `http://localhost:5000`

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/analyze` | Analyze code, return findings (not saved) |
| POST | `/api/analyze/save` | Analyze and save to MongoDB |
| GET | `/api/reports` | Get all saved audit reports |
| GET | `/api/reports/:id` | Get single report by ID |
| DELETE | `/api/reports/:id` | Delete a report |
| GET | `/api/dashboard` | Get stats and recent audits |

---

## Example Request

### POST /api/analyze
```json
{
  "language": "javascript",
  "code": "const query = 'SELECT * FROM users WHERE id = ' + userId;"
}
```

### Response
```json
{
  "success": true,
  "data": {
    "findings": [
      {
        "name": "SQL Injection",
        "severity": "High",
        "description": "...",
        "recommendation": "...",
        "lineNumber": 1
      }
    ],
    "securityScore": 80,
    "riskLevel": "Medium",
    "totalVulnerabilities": 1,
    "highCount": 1,
    "mediumCount": 0,
    "lowCount": 0
  }
}
```

---

## Security Score Calculation
- Start: 100 points
- High severity: -20 points each
- Medium severity: -10 points each
- Low severity: -5 points each

## Vulnerabilities Detected
1. SQL Injection (High)
2. Cross-Site Scripting / XSS (High)
3. Hardcoded Passwords (High)
4. Command Injection (High)
5. Sensitive Data Exposure (Medium)
6. Insecure File Handling (Medium)
7. Weak Authentication (Medium)
8. Debug Information Leakage (Low)
