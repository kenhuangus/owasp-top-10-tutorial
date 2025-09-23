
export type Vulnerability = {
  id: string;
  slug: string;
  title: string;
  description: string;
  longDescription: string;
  impact: string;
  diagramId: string;
  vulnerableCode: {
    language: string;
    code: string;
  };
  secureCode: {
    language: string;
    code: string;
  };
};

export const owaspTop10: Vulnerability[] = [
  {
    id: 'A01',
    slug: 'broken-access-control',
    title: 'Broken Access Control',
    description: 'Enforcing restrictions on authenticated users.',
    longDescription: '• Restricts user actions based on permissions.\n• Failures lead to unauthorized data access/modification.\n• Common exploits: IDOR, privilege escalation, path traversal.',
    impact: 'Unauthorized access to sensitive data or functionality, potentially leading to full system compromise.',
    diagramId: 'diagram-broken-access-control',
    vulnerableCode: {
      language: 'Node.js',
      code: `app.get('/user/:id/invoice', (req, res) => {
  // Insecure: No check to see if the logged-in user
  // is authorized to see this invoice.
  const invoice = Invoice.find({ id: req.params.id });
  res.render('invoice', { invoice });
});`,
    },
    secureCode: {
      language: 'Node.js',
      code: `app.get('/user/:id/invoice', (req, res) => {
  // Secure: Check if the logged-in user owns the invoice.
  if (req.user.id !== req.params.id) {
    return res.status(403).send('Forbidden');
  }
  const invoice = Invoice.find({ id: req.params.id, userId: req.user.id });
  res.render('invoice', { invoice });
});`,
    },
  },
  {
    id: 'A02',
    slug: 'cryptographic-failures',
    title: 'Cryptographic Failures',
    description: 'Failures related to cryptography.',
    longDescription: '• Failures in cryptography leading to data exposure.\n• Common issues: cleartext data, weak algorithms, poor key management.\n• Example: Using MD5 for hashing passwords.',
    impact: 'Exposure of sensitive data like passwords, credit card numbers, and personal information.',
    diagramId: 'diagram-cryptographic-failures',
    vulnerableCode: {
      language: 'Java',
      code: `// Vulnerable: Using a weak hashing algorithm (MD5)
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hashedPassword = md.digest(password.getBytes());`,
    },
    secureCode: {
      language: 'Java',
      code: `// Secure: Using a strong, salted, and peppered hashing algorithm (Argon2)
Argon2 argon2 = Argon2Factory.create();
String hash = argon2.hash(10, 65536, 1, password.toCharArray());`,
    },
  },
  {
    id: 'A03',
    slug: 'injection',
    title: 'Injection',
    description: 'Untrusted data sent to an interpreter.',
    longDescription: '• Untrusted data sent to a code interpreter.\n• Examples: SQL, NoSQL, OS command, LDAP injection.\n• Tricks interpreter into executing unintended commands.',
    impact: 'Can result in data loss, corruption, or disclosure to unauthorized parties, leading to denial of service or complete host takeover.',
    diagramId: 'diagram-injection',
    vulnerableCode: {
      language: 'PHP',
      code: `$username = $_POST['username'];
// Vulnerable: Raw user input is concatenated into the SQL query
$query = "SELECT * FROM users WHERE username = '" . $username . "'";
$result = mysqli_query($conn, $query);`,
    },
    secureCode: {
      language: 'PHP',
      code: `$username = $_POST['username'];
// Secure: Using prepared statements (parameterized queries)
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();`,
    },
  },
  {
    id: 'A04',
    slug: 'insecure-design',
    title: 'Insecure Design',
    description: 'Missing or ineffective control design.',
    longDescription: '• Flaws in application design and architecture.\n• "Missing or ineffective control design".\n• Security should be foundational, not an afterthought.',
    impact: 'Vulnerabilities can be deeply embedded in the application, making them difficult to fix and potentially leading to a wide range of security issues.',
    diagramId: 'diagram-insecure-design',
    vulnerableCode: {
      language: 'Concept',
      code: `// Flawed Design: A password reset process that sends the old
// password back to the user via email.
function resetPassword(email) {
  const user = findUserByEmail(email);
  const oldPassword = user.getPassword(); // Design flaw
  Email.send(email, "Your password is: " + oldPassword);
}`,
    },
    secureCode: {
      language: 'Concept',
      code: `// Secure Design: A password reset process that sends a
// time-limited, single-use token.
function resetPassword(email) {
  const user = findUserByEmail(email);
  const token = generateResetToken(user.id);
  const resetLink = "https://example.com/reset?token=" + token;
  Email.send(email, "Reset your password here: " + resetLink);
}`,
    },
  },
  {
    id: 'A05',
    slug: 'security-misconfiguration',
    title: 'Security Misconfiguration',
    description: 'Incorrect security configurations.',
    longDescription: '• Occurs at any level of the application stack.\n• Examples: debug mode in production, unnecessary open ports, default passwords.\n• Often easy for attackers to exploit.',
    impact: 'Can lead to unauthorized access, sensitive data exposure, or full system compromise, often with minimal effort from an attacker.',
    diagramId: 'diagram-security-misconfiguration',
    vulnerableCode: {
      language: 'YAML (Config)',
      code: `# Vulnerable: Directory listing is enabled on a web server,
# potentially exposing sensitive files.
- name: Configure Apache
  apache2_module:
    name: autoindex
    state: present`,
    },
    secureCode: {
      language: 'YAML (Config)',
      code: `# Secure: Directory listing is explicitly disabled.
- name: Configure Apache
  apache2_module:
    name: autoindex
    state: absent`,
    },
  },
  {
    id: 'A06',
    slug: 'vulnerable-and-outdated-components',
    title: 'Vulnerable and Outdated Components',
    description: 'Components with known vulnerabilities.',
    longDescription: '• Using libraries, frameworks with known vulnerabilities.\n• Components run with the same privileges as the application.\n• Can undermine application defenses.',
    impact: 'Can range from minor issues to complete system takeover, depending on the vulnerability in the component.',
    diagramId: 'diagram-vulnerable-components',
    vulnerableCode: {
      language: 'package.json',
      code: `// Vulnerable: Using an old, known-vulnerable version of a library.
{
  "dependencies": {
    "express": "4.16.0" 
  }
}`,
    },
    secureCode: {
      language: 'package.json',
      code: `// Secure: Using an updated, patched version of the library.
{
  "dependencies": {
    "express": "^4.19.2"
  }
}`,
    },
  },
  {
    id: 'A07',
    slug: 'identification-and-authentication-failures',
    title: 'Identification and Authentication Failures',
    description: 'Incorrect authentication and session management.',
    longDescription: '• Incorrect implementation of identity and session management.\n• Allows attackers to compromise passwords, keys, or session tokens.\n• Common attacks: brute force, credential stuffing.',
    impact: 'Attackers can gain control of user accounts and potentially the entire system.',
    diagramId: 'diagram-authentication-failures',
    vulnerableCode: {
      language: 'Python',
      code: `# Vulnerable: No rate limiting on login attempts
@app.route('/login', methods=['POST'])
def login():
    # ... check username and password ...
    if is_valid:
        return 'Logged in'
    else:
        return 'Invalid credentials'`,
    },
    secureCode: {
      language: 'Python',
      code: `# Secure: Implements rate limiting and account lockout
@app.route('/login', methods=['POST'])
@rate_limit(limit=5, per=60) # 5 attempts per minute
def login():
    # ... check for locked account ...
    # ... check username and password ...
    if is_valid:
        # ... reset failed attempts ...
        return 'Logged in'
    else:
        # ... increment failed attempts, lock if needed ...
        return 'Invalid credentials'`,
    },
  },
  {
    id: 'A08',
    slug: 'software-and-data-integrity-failures',
    title: 'Software and Data Integrity Failures',
    description: 'Verifying software updates and data integrity.',
    longDescription: '• Lack of protection against integrity violations.\n• Using plugins/libraries from untrusted sources.\n• Insecure CI/CD pipelines are a major risk.',
    impact: 'Can lead to the execution of malicious code, unauthorized system modifications, or the compromise of sensitive data.',
    diagramId: 'diagram-integrity-failures',
    vulnerableCode: {
      language: 'Shell',
      code: `# Vulnerable: Fetching and executing a script without integrity checks.
curl http://example.com/install.sh | bash`,
    },
    secureCode: {
      language: 'Shell',
      code: `# Secure: Fetching script, verifying its hash, then executing.
wget http://example.com/install.sh
echo "expected_hash install.sh" | sha256sum -c -
if [ $? -eq 0 ]; then
  bash install.sh
fi`,
    },
  },
  {
    id: 'A09',
    slug: 'security-logging-and-monitoring-failures',
    title: 'Security Logging and Monitoring Failures',
    description: 'Insufficient logging and monitoring.',
    longDescription: '• Insufficient logging, monitoring, and incident response.\n• Allows attackers to persist and pivot.\n• Breach detection time is often over 200 days.',
    impact: 'Delays in detecting and responding to attacks, increasing the potential damage and allowing attackers to remain undetected for long periods.',
    diagramId: 'diagram-logging-failures',
    vulnerableCode: {
      language: 'Java',
      code: `// Vulnerable: A critical security event (failed login) is not logged.
try {
  // ... authentication logic ...
} catch (AuthenticationException e) {
  // Return an error but don't log the attempt.
  return "Authentication Failed";
}`,
    },
    secureCode: {
      language: 'Java',
      code: `// Secure: Failed login attempts are logged for monitoring.
try {
  // ... authentication logic ...
} catch (AuthenticationException e) {
  logger.warn("Failed login attempt for user: " + username);
  return "Authentication Failed";
}`,
    },
  },
  {
    id: 'A10',
    slug: 'server-side-request-forgery',
    title: 'Server-Side Request Forgery (SSRF)',
    description: 'Server requests to an arbitrary domain.',
    longDescription: '• Application fetches a remote resource without validating user-supplied URL.\n• Attacker can make the server send crafted requests.\n• Used to probe internal networks or attack internal services.',
    impact: 'Can lead to information disclosure, denial of service, and remote code execution against internal systems.',
    diagramId: 'diagram-ssrf',
    vulnerableCode: {
      language: 'Python (Flask)',
      code: `@app.route('/fetch-image')
def fetch_image():
    # Vulnerable: fetches any URL provided by the user.
    image_url = request.args.get('url')
    response = requests.get(image_url)
    return response.content`,
    },
    secureCode: {
      language: 'Python (Flask)',
      code: `@app.route('/fetch-image')
def fetch_image():
    # Secure: validates URL against an allow-list.
    image_url = request.args.get('url')
    if not is_allowed_domain(image_url):
        return "Invalid domain", 400
    
    response = requests.get(image_url)
    return response.content`,
    },
  },
];

    