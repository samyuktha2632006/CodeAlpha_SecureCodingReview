// Vulnerability Detection Engine
// Detects common security issues using pattern matching

const vulnerabilityRules = [
  {
    name: 'SQL Injection',
    severity: 'High',
    patterns: [
      /query\s*\(\s*[`"'].*\$\{/i,
      /query\s*\(\s*["'`].*\+\s*(req\.|user|input)/i,
      /execute\s*\(\s*["'`].*SELECT.*\+/i,
      /db\.query\s*\(\s*`[^`]*\$\{/i,
    ],
    description:
      'User input is directly concatenated into SQL queries without sanitization.',
    impact:
      'Attackers can manipulate queries to read, modify, or delete database data.',
    recommendation:
      'Use parameterized queries or prepared statements instead of string concatenation.',
    secureExample: `// Insecure:\ndb.query("SELECT * FROM users WHERE id = " + userId);\n\n// Secure:\ndb.query("SELECT * FROM users WHERE id = ?", [userId]);`,
  },
  {
    name: 'Cross-Site Scripting (XSS)',
    severity: 'High',
    patterns: [
      /innerHTML\s*=\s*(req\.|user|input|params|query)/i,
      /document\.write\s*\(\s*(req\.|user|input)/i,
      /res\.send\s*\(\s*req\.(body|query|params)/i,
      /innerHTML\s*=\s*`[^`]*\$\{/i,
    ],
    description:
      'Unescaped user input is rendered directly into the HTML of a page.',
    impact:
      'Attackers can inject malicious scripts that steal cookies, session tokens, or redirect users.',
    recommendation:
      'Always sanitize and escape user input before rendering. Use libraries like DOMPurify.',
    secureExample: `// Insecure:\nelement.innerHTML = userInput;\n\n// Secure:\nelement.textContent = userInput;\n// Or use DOMPurify:\nelement.innerHTML = DOMPurify.sanitize(userInput);`,
  },
  {
    name: 'Hardcoded Password',
    severity: 'High',
    patterns: [
      /password\s*=\s*["'][^"']{4,}["']/i,
      /passwd\s*=\s*["'][^"']{4,}["']/i,
      /secret\s*=\s*["'][^"']{4,}["']/i,
      /api_key\s*=\s*["'][^"']{8,}["']/i,
      /apiKey\s*=\s*["'][^"']{8,}["']/i,
    ],
    description:
      'Credentials or secrets are hardcoded directly in the source code.',
    impact:
      'Anyone with access to the codebase can extract credentials. Secrets exposed in version control cannot be easily revoked.',
    recommendation:
      'Store secrets in environment variables (.env files) and never commit them to version control.',
    secureExample: `// Insecure:\nconst password = "admin123";\n\n// Secure:\nconst password = process.env.DB_PASSWORD;`,
  },
  {
    name: 'Sensitive Data Exposure',
    severity: 'Medium',
    patterns: [
      /console\.log\s*\(.*password/i,
      /console\.log\s*\(.*token/i,
      /console\.log\s*\(.*secret/i,
      /res\.json\s*\(\s*\{.*password/i,
      /res\.send\s*\(.*password/i,
    ],
    description:
      'Sensitive data such as passwords or tokens are logged or sent in API responses.',
    impact:
      'Sensitive information can be exposed in server logs, browser consoles, or API responses.',
    recommendation:
      'Never log sensitive data. Remove password fields from API responses using field selection.',
    secureExample: `// Insecure:\nconsole.log("User password:", password);\n\n// Secure:\n// Never log passwords. Remove from response:\nconst { password, ...safeUser } = user;\nres.json(safeUser);`,
  },
  {
    name: 'Command Injection',
    severity: 'High',
    patterns: [
      /exec\s*\(\s*[`"'].*\$\{/i,
      /exec\s*\(\s*["'`].*\+\s*(req\.|user|input)/i,
      /execSync\s*\(\s*[`"'].*\$\{/i,
      /child_process.*exec.*req\./i,
      /shell\s*=\s*true/i,
    ],
    description:
      'User input is passed directly to system command execution functions.',
    impact:
      'Attackers can execute arbitrary system commands, potentially gaining full server control.',
    recommendation:
      'Never pass user input to exec/execSync. Use safe APIs or validate/whitelist input strictly.',
    secureExample: `// Insecure:\nconst { exec } = require('child_process');\nexec('ls ' + userInput);\n\n// Secure:\n// Use specific APIs instead of shell commands\nconst fs = require('fs');\nfs.readdir(safePath, callback);`,
  },
  {
    name: 'Insecure File Handling',
    severity: 'Medium',
    patterns: [
      /readFile\s*\(\s*req\.(body|query|params)/i,
      /readFileSync\s*\(\s*req\.(body|query|params)/i,
      /path\.join\s*\(.*req\.(body|query|params)/i,
      /fs\.(read|write).*req\./i,
    ],
    description:
      'User-controlled input is used directly in file system operations without validation.',
    impact:
      'Attackers can use path traversal (../../etc/passwd) to read or write arbitrary files.',
    recommendation:
      'Validate and sanitize file paths. Use path.basename() to strip directory traversal.',
    secureExample: `// Insecure:\nfs.readFile(req.query.filename, callback);\n\n// Secure:\nconst safeName = path.basename(req.query.filename);\nconst fullPath = path.join(__dirname, 'uploads', safeName);\nfs.readFile(fullPath, callback);`,
  },
  {
    name: 'Weak Authentication',
    severity: 'Medium',
    patterns: [
      /md5\s*\(/i,
      /createHash\s*\(\s*["']md5["']\s*\)/i,
      /createHash\s*\(\s*["']sha1["']\s*\)/i,
      /jwt\.sign\s*\(.*algorithm.*none/i,
      /expiresIn.*["'](\d{4,}[smhd]?|never)["']/i,
    ],
    description:
      'Weak or outdated hashing algorithms (MD5, SHA1) are used for passwords or tokens.',
    impact:
      'Passwords hashed with weak algorithms can be cracked quickly using rainbow tables or brute force.',
    recommendation:
      'Use bcrypt, argon2, or scrypt for password hashing. Use strong JWT algorithms like HS256 or RS256.',
    secureExample: `// Insecure:\nconst hash = md5(password);\n\n// Secure:\nconst bcrypt = require('bcrypt');\nconst hash = await bcrypt.hash(password, 12);`,
  },
  {
    name: 'Debug Information Leakage',
    severity: 'Low',
    patterns: [
      /res\.json\s*\(\s*\{\s*error\s*:/i,
      /res\.send\s*\(\s*err\.stack/i,
      /res\.json\s*\(\s*err\s*\)/i,
      /console\.error\s*\(\s*err\s*\)/i,
      /app\.use\s*\(\s*(err|error)\s*=>/i,
    ],
    description:
      'Internal error details, stack traces, or debug info are exposed to the client.',
    impact:
      'Attackers gain insight into server internals, file paths, and application structure.',
    recommendation:
      'Return generic error messages to clients. Log detailed errors server-side only.',
    secureExample: `// Insecure:\nres.json({ error: err.stack });\n\n// Secure:\nconsole.error(err); // log server-side only\nres.status(500).json({ message: "Internal server error" });`,
  },
];

function calculateScore(findings) {
  let score = 100;
  for (const f of findings) {
    if (f.severity === 'High') score -= 20;
    else if (f.severity === 'Medium') score -= 10;
    else if (f.severity === 'Low') score -= 5;
  }
  return Math.max(0, score);
}

function getRiskLevel(score) {
  if (score >= 90) return 'Safe';
  if (score >= 70) return 'Low';
  if (score >= 50) return 'Medium';
  if (score >= 30) return 'High';
  return 'Critical';
}

function analyzeCode(code, language) {
  const findings = [];
  const lines = code.split('\n');

  for (const rule of vulnerabilityRules) {
    for (const pattern of rule.patterns) {
      let matched = false;
      let lineNumber = null;

      lines.forEach((line, idx) => {
        if (!matched && pattern.test(line)) {
          matched = true;
          lineNumber = idx + 1;
        }
      });

      if (matched) {
        // Avoid duplicate vulnerability names
        if (!findings.find((f) => f.name === rule.name)) {
          findings.push({
            name: rule.name,
            severity: rule.severity,
            description: rule.description,
            impact: rule.impact,
            recommendation: rule.recommendation,
            secureExample: rule.secureExample,
            lineNumber,
          });
        }
        break;
      }
    }
  }

  const securityScore = calculateScore(findings);
  const riskLevel = getRiskLevel(securityScore);
  const highCount = findings.filter((f) => f.severity === 'High').length;
  const mediumCount = findings.filter((f) => f.severity === 'Medium').length;
  const lowCount = findings.filter((f) => f.severity === 'Low').length;

  return {
    findings,
    securityScore,
    riskLevel,
    totalVulnerabilities: findings.length,
    highCount,
    mediumCount,
    lowCount,
  };
}

module.exports = { analyzeCode };
