
export type Vulnerability = {
  id: string;
  slug: string;
  title: string;
  description: string;
  longDescription: string;
  impact: string;
  diagramCode: string;
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
    longDescription: `• Restricts user actions based on permissions.
• Failures lead to unauthorized data access/modification.
• Common exploits: IDOR, privilege escalation, path traversal.`,
    impact: 'Unauthorized access to sensitive data or functionality, potentially leading to full system compromise.',
    diagramCode: `flowchart TD
    subgraph Legitimate User
        A["User requests '/user/123/profile'"] --> B["Server checks authentication"];
        B --> C["User is authenticated"];
        C --> D["FAIL: No authorization check"];
        D --> E["Server returns User 123's profile"];
    end
    subgraph Attacker
        F["Attacker changes ID in URL to '/user/456/profile'"] --> G["Server checks authentication"];
        G --> H["Attacker is authenticated as themselves"];
        H --> I["FAIL: No authorization check for requested resource"];
        I --> J["Server returns User 456's profile"];
    end`,
    vulnerableCode: {
      language: 'Node.js',
      code: `app.get('/user/:id/invoice', (req, res) => {
  <strong>// Insecure: No check to see if the logged-in user
  // is authorized to see this invoice.</strong>
  const invoice = Invoice.find({ id: req.params.id });
  res.render('invoice', { invoice });
});`,
    },
    secureCode: {
      language: 'Node.js',
      code: `app.get('/user/:id/invoice', (req, res) => {
  <strong>// Secure: Check if the logged-in user owns the invoice.
  if (req.user.id !== req.params.id) {
    return res.status(403).send('Forbidden');
  }</strong>
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
    longDescription: `• Failures in cryptography leading to data exposure.
• Common issues: cleartext data, weak algorithms, poor key management.
• Example: Using MD5 for hashing passwords.`,
    impact: 'Exposure of sensitive data like passwords, credit card numbers, and personal information.',
    diagramCode: `flowchart TD
    subgraph Initial Storage
        A["User provides password"] --> B["Server receives password"];
        B --> C["FAIL: Hashes with weak algorithm e.g., MD5"];
        C --> D["Stores weak hash in database"];
    end
    subgraph Attack
        E["Attacker gains database access"] --> F["Retrieves all weakly-hashed passwords"];
        F --> G["Uses pre-computed rainbow table to find MD5 matches"];
        G --> H["Plaintext passwords revealed"];
    end`,
    vulnerableCode: {
      language: 'Java',
      code: `<strong>// Vulnerable: Using a weak hashing algorithm (MD5)
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hashedPassword = md.digest(password.getBytes());</strong>`,
    },
    secureCode: {
      language: 'Java',
      code: `<strong>// Secure: Using a strong, salted, and peppered hashing algorithm (Argon2)
Argon2 argon2 = Argon2Factory.create();
String hash = argon2.hash(10, 65536, 1, password.toCharArray());</strong>`,
    },
  },
  {
    id: 'A03',
    slug: 'injection',
    title: 'Injection',
    description: 'Untrusted data sent to an interpreter.',
    longDescription: `• Occurs when untrusted data is sent to a code interpreter.
• SQL injection: Malicious SQL statements are inserted into an entry field for execution.
• Cross-Site Scripting (XSS): Malicious scripts are injected into otherwise benign and trusted websites.
• Other types: NoSQL, OS command, LDAP injection.`,
    impact: 'Can result in data loss, corruption, or disclosure to unauthorized parties, leading to denial of service or complete host takeover.',
    diagramCode: `flowchart TD
    subgraph "XSS Attack"
        A["Attacker crafts a URL with a malicious script: /search?q=<script>alert(1)</script>"] --> B["Attacker tricks a victim into clicking the link"];
        B --> C["Victim's browser sends the request to the web application"];
        C --> D["Web application server"];
        D --> E["FAIL: The application takes the query parameter 'q' and renders it directly into the HTML response without sanitization"];
        E --> F["The victim's browser receives the response with the malicious script inside the HTML"];
        F --> G["The browser executes the script, which could steal session cookies, redirect the user, or perform other malicious actions"];
    end`,
    vulnerableCode: {
      language: 'JSP',
      code: `<!-- Vulnerable: User input is directly included in the page -->
<% String query = request.getParameter("q"); %>
<p>You searched for: <strong><%= query %></strong></p>`,
    },
    secureCode: {
      language: 'JSP',
      code: `<!-- Secure: User input is properly escaped/encoded before being displayed -->
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<% String query = request.getParameter("q"); %>
<p>You searched for: <strong><c:out value="$\\{param.q}" /></strong></p>`,
    },
  },
  {
    id: 'A04',
    slug: 'insecure-design',
    title: 'Insecure Design',
    description: 'Missing or ineffective control design.',
    longDescription: `• Flaws in application design and architecture.
• "Missing or ineffective control design".
• Security should be foundational, not an afterthought.`,
    impact: 'Vulnerabilities can be deeply embedded in the application, making them difficult to fix and potentially leading to a wide range of security issues.',
    diagramCode: `flowchart TD
    subgraph "Flawed Design: Ticket Purchase"
        A["User selects 2 tickets at $10 each"] --> B["Client-side JS calculates total: $20"];
        B --> C["Request sent to server: { quantity: 2, total: 20 }"];
        C --> D["Server receives data"];
        D --> E["FAIL: Server trusts the 'total' from client instead of recalculating"];
        E --> F["Payment processor is charged $20"];
    end
    subgraph "Attack Scenario"
        G["Attacker selects 2 tickets at $10 each"] --> H["Attacker manipulates client-side request"];
        H --> I["Request sent to server: { quantity: 2, total: 1 }"];
        I --> J["Server receives data"];
        J --> K["FAIL: Server trusts the 'total' from client instead of recalculating"];
        K --> L["Payment processor is charged $1"];
    end`,
    vulnerableCode: {
      language: 'Concept',
      code: `<strong>// Flawed Design: A password reset process that sends the old
// password back to the user via email.
function resetPassword(email) {
  const user = findUserByEmail(email);
  const oldPassword = user.getPassword(); // Design flaw
  Email.send(email, "Your password is: " + oldPassword);
}</strong>`,
    },
    secureCode: {
      language: 'Concept',
      code: `<strong>// Secure Design: A password reset process that sends a
// time-limited, single-use token.
function resetPassword(email) {
  const user = findUserByEmail(email);
  const token = generateResetToken(user.id);
  const resetLink = "https://example.com/reset?token=" + token;
  Email.send(email, "Reset your password here: " + resetLink);
}</strong>`,
    },
  },
  {
    id: 'A05',
    slug: 'security-misconfiguration',
    title: 'Security Misconfiguration',
    description: 'Incorrect security configurations.',
    longDescription: `• Occurs at any level of the application stack.
• Examples: debug mode in production, unnecessary open ports, default passwords.
• Often easy for attackers to exploit.`,
    impact: 'Can lead to unauthorized access, sensitive data exposure, or full system compromise, often with minimal effort from an attacker.',
    diagramCode: `flowchart TD
    subgraph "Cloud Storage Misconfiguration"
        A["Admin configures S3 bucket"] --> B["FAIL: Sets permissions to public read/write"];
        C["Attacker scans for open S3 buckets"] --> D["Finds public bucket"];
        D --> E["Accesses/modifies sensitive files"];
    end
    subgraph "Default Credentials"
        F["Admin deploys new server"] --> G["FAIL: Leaves default admin password 'admin:password'"];
        H["Attacker scans for admin login pages"] --> I["Tries common default credentials"];
        I --> J["Gains full admin access to the server"];
    end`,
    vulnerableCode: {
      language: 'YAML (Config)',
      code: `<strong># Vulnerable: Directory listing is enabled on a web server,
# potentially exposing sensitive files.
- name: Configure Apache
  apache2_module:
    name: autoindex
    state: present</strong>`,
    },
    secureCode: {
      language: 'YAML (Config)',
      code: `<strong># Secure: Directory listing is explicitly disabled.
- name: Configure Apache
  apache2_module:
    name: autoindex
    state: absent</strong>`,
    },
  },
  {
    id: 'A06',
    slug: 'vulnerable-and-outdated-components',
    title: 'Vulnerable and Outdated Components',
    description: 'Components with known vulnerabilities.',
    longDescription: `• Using libraries, frameworks with known vulnerabilities.
• Components run with the same privileges as the application.
• Can undermine application defenses.`,
    impact: 'Can range from minor issues to complete system takeover, depending on the vulnerability in the component.',
    diagramCode: `flowchart TD
    A["Developer uses outdated library 'image-lib 1.2'"] --> B["Application is deployed"];
    C["A security vulnerability CVE-2023-1234 is found in 'image-lib 1.2'"] --> D["A patched version 'image-lib 1.3' is released"];
    E["Attacker scans the internet for sites using 'image-lib 1.2'"] --> F["Finds the vulnerable application"];
    F --> G["FAIL: Application is running the vulnerable code"];
    G --> H["Attacker exploits the CVE to achieve Remote Code Execution"];
    end`,
    vulnerableCode: {
      language: 'package.json',
      code: `{
  "dependencies": {
    <strong>"express": "4.16.0"</strong>
  }
}`,
    },
    secureCode: {
      language: 'package.json',
      code: `{
  "dependencies": {
    <strong>"express": "^4.19.2"</strong>
  }
}`,
    },
  },
  {
    id: 'A07',
    slug: 'identification-and-authentication-failures',
    title: 'Identification and Authentication Failures',
    description: 'Incorrect authentication and session management.',
    longDescription: `• Incorrect implementation of identity and session management.
• Allows attackers to compromise passwords, keys, or session tokens.
• Common attacks: brute force, credential stuffing.`,
    impact: 'Attackers can gain control of user accounts and potentially the entire system.',
    diagramCode: `flowchart TD
    subgraph "Attack Vector: No Rate Limiting"
      A["Attacker picks a target username"] --> B["FAIL: Login form has no rate limit"];
      B --> C["Attacker uses a script to try millions of passwords brute force"];
      C --> D["Eventually, the correct password is found"];
      D --> E["Attacker gains access to the account"];
    end
    subgraph "Attack Vector: Weak Session IDs"
        F["User logs in"] --> G["Server generates a session ID"];
        G --> H["FAIL: Session ID is easily guessable e.g., sequential numbers"];
        H --> I["Attacker's script guesses valid session IDs"];
        I --> J["Attacker hijacks a valid user session"];
    end`,
    vulnerableCode: {
      language: 'Python',
      code: `<strong># Vulnerable: No rate limiting on login attempts</strong>
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
      code: `<strong># Secure: Implements rate limiting and account lockout</strong>
@app.route('/login', methods=['POST'])
<strong>@rate_limit(limit=5, per=60) // 5 attempts per minute</strong>
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
    longDescription: `• Lack of protection against integrity violations.
• Using plugins/libraries from untrusted sources.
• Insecure CI/CD pipelines are a major risk.`,
    impact: 'Can lead to the execution of malicious code, unauthorized system modifications, or the compromise of sensitive data.',
    diagramCode: `flowchart TD
    subgraph Insecure Deserialization Attack
      A["Application serializes an object and stores it in a user's cookie"] --> B["User receives the cookie with serialized data"];
      B --> C["Attacker modifies the serialized data in the cookie to include a malicious payload"];
      C --> D["Attacker sends the modified cookie back to the application"];
      D --> E["FAIL: Application deserializes the data without validation or integrity checks"];
      E --> F["The malicious payload is executed on the server, leading to Remote Code Execution"];
    end
    subgraph "Insecure Update Pipeline"
        G["CI/CD pipeline pulls dependencies from a public repository"] --> H["FAIL: No integrity check e.g., hash validation on downloaded packages"];
        H --> I["An attacker compromises the public repository and injects malicious code into a dependency"];
        I --> J["The compromised dependency is built into the application"];
        J --> K["The malicious code runs with the application's privileges"];
    end`,
    vulnerableCode: {
      language: 'Shell',
      code: `<strong># Vulnerable: Fetching and executing a script without integrity checks.
curl http://example.com/install.sh | bash</strong>`,
    },
    secureCode: {
      language: 'Shell',
      code: `<strong># Secure: Fetching script, verifying its hash, then executing.
wget http://example.com/install.sh
echo "expected_hash install.sh" | sha256sum -c -
if [ $? -eq 0 ]; then
  bash install.sh
fi</strong>`,
    },
  },
  {
    id: 'A09',
    slug: 'security-logging-and-monitoring-failures',
    title: 'Security Logging and Monitoring Failures',
    description: 'Insufficient logging and monitoring.',
    longDescription: `• Insufficient logging, monitoring, and incident response.
• Allows attackers to persist and pivot.
• Breach detection time is often over 200 days.`,
    impact: 'Delays in detecting and responding to attacks, increasing the potential damage and allowing attackers to remain undetected for long periods.',
    diagramCode: `flowchart TD
    A["Attacker performs suspicious activities e.g., multiple failed logins, probing for vulnerabilities"] --> B["Application Server"];
    B --> C["FAIL: Application does not log these security-relevant events"];
    C --> D["No logs are sent to a monitoring system"];
    D --> E["No alerts are triggered"];
    E --> F["Attacker continues their attack, eventually succeeding"];
    F --> G["FAIL: The successful breach is also not logged properly"];
    G --> H["The attacker remains undetected for an extended period, exfiltrating data or causing damage"];
    end`,
    vulnerableCode: {
      language: 'Java',
      code: `// Vulnerable: A critical security event (failed login) is not logged.
try {
  // ... authentication logic ...
} catch (AuthenticationException e) {
  <strong>// Return an error but don't log the attempt.
  return "Authentication Failed";</strong>
}`,
    },
    secureCode: {
      language: 'Java',
      code: `// Secure: Failed login attempts are logged for monitoring.
try {
  // ... authentication logic ...
} catch (AuthenticationException e) {
  <strong>logger.warn("Failed login attempt for user: " + username);</strong>
  return "Authentication Failed";
}`,
    },
  },
  {
    id: 'A10',
    slug: 'server-side-request-forgery',
    title: 'Server-Side Request Forgery (SSRF)',
    description: 'Server requests to an arbitrary domain.',
    longDescription: `• Application fetches a remote resource without validating user-supplied URL.
• Attacker can make the server send crafted requests.
• Used to probe internal networks or attack internal services.`,
    impact: 'Can lead to information disclosure, denial of service, and remote code execution against internal systems.',
    diagramCode: `flowchart TD
    subgraph Internet
      A["Attacker"]
    end
    subgraph "DMZ / Public Network"
      B["Vulnerable Web Application"]
    end
    subgraph "Internal Network"
      C["Internal Service e.g., Admin Panel at 192.168.1.10"]
      D["Internal Database at 192.168.1.11"]
    end
    A -- "Sends request with malicious URL: 'http://192.168.1.10/admin'" --> B;
    B -- "FAIL: Server does not validate the URL" --> C;
    C -- "Returns internal admin page content" --> B;
    B -- "Forwards internal content to attacker" --> A;
    `,
    vulnerableCode: {
      language: 'Python (Flask)',
      code: `@app.route('/fetch-image')
def fetch_image():
    <strong># Vulnerable: fetches any URL provided by the user.
    image_url = request.args.get('url')
    response = requests.get(image_url)</strong>
    return response.content`,
    },
    secureCode: {
      language: 'Python (Flask)',
      code: `@app.route('/fetch-image')
def fetch_image():
    <strong># Secure: validates URL against an allow-list.
    image_url = request.args.get('url')
    if not is_allowed_domain(image_url):
        return "Invalid domain", 400</strong>
    
    response = requests.get(image_url)
    return response.content`,
    },
  },
];
