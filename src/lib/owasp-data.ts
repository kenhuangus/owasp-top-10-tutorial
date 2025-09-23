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
    description: 'Failures in enforcing restrictions on what authenticated users are allowed to do.',
    longDescription: 'Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user\'s limits. Common access control vulnerabilities include insecure direct object references (IDOR), privilege escalation, and path traversal.',
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
    description: 'Failures related to cryptography, which often lead to exposure of sensitive data.',
    longDescription: 'This category is for failures related to cryptography (or lack thereof), which often lead to exposure of sensitive data. A common mistake is transmitting data in cleartext, using weak or outdated cryptographic algorithms, or poor key management. Using deprecated hash functions like MD5 for passwords is a classic example.',
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
    description: 'Flaws that allow untrusted data to be sent to an interpreter as part of a command or query.',
    longDescription: 'Injection flaws, such as SQL, NoSQL, OS command, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query. The attacker’s hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization. The most common is SQL injection.',
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
    description: 'A category representing different weaknesses, expressed as "missing or ineffective control design".',
    longDescription: 'Insecure Design is a broad category representing different weaknesses, expressed as "missing or ineffective control design." It focuses on flaws in the design and architecture of an application. A key principle is "secure by design," which means that security is a foundational part of the development process, not an afterthought.',
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
    description: 'Missing or incorrect security configurations.',
    longDescription: 'Security misconfiguration can happen at any level of an application stack, including the network services, platform, web server, application server, database, frameworks, and custom code. Examples include running in debug mode in production, having unnecessary ports open, or using default accounts and passwords.',
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
    description: 'Using components with known vulnerabilities.',
    longDescription: 'Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. Applications and APIs using components with known vulnerabilities may undermine application defenses and enable various attacks and impacts.',
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
    description: 'Incorrectly implemented authentication and session management functions.',
    longDescription: 'Confirmation of user identity, authentication, and session management is critical to protect against authentication-related attacks. Failures can allow attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users\' identities temporarily or permanently. Brute force attacks and credential stuffing are common.',
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
    description: 'Failures related to software updates and data without verifying integrity.',
    longDescription: 'Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs). Insecure CI/CD pipelines can introduce the potential for unauthorized access, malicious code, or system compromise.',
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
    longDescription: 'Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper, extract, or destroy data. Most breach studies show time to detect a breach is over 200 days, typically detected by external parties rather than internal processes or monitoring.',
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
    description: 'Flaws that allow a server to make requests to an arbitrary domain.',
    longDescription: 'SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to a destination of the attacker\'s choosing. This can be used to probe internal networks, attack internal services, or access cloud provider metadata endpoints.',
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
