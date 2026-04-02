# AI Secure Code Inspector — Vulnerability Report

**Target:** OWASP Juice Shop  
**Scope:** 10 files (routes, lib, models, frontend)  
**Total verified findings:** 31  

---

## Finding 1: A03 - Injection

**File:** `routes/login.ts`  
**Line range:** 24  
**Confidence:** 0.98  

### Risk Summary
User input from req.body.email is concatenated directly into a SQL query without parameterization. An attacker can inject SQL syntax (e.g., ' OR '1'='1) to bypass authentication, enumerate users, or extract sensitive data from the database.

### Fix Recommendation
Replace the raw SQL query with parameterized queries using Sequelize's where clause: models.sequelize.query('SELECT * FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL', { replacements: [req.body.email || '', security.hash(req.body.password || '')], model: UserModel, plain: true })

---

## Finding 2: A03 - Injection

**File:** `routes/search.ts`  
**Line range:** 18-19  
**Confidence:** 0.99  

### Risk Summary
User input from req.query.q is concatenated directly into a SQL query without parameterization or prepared statements. An attacker can inject SQL syntax (e.g., UNION SELECT, OR 1=1) to bypass the search logic, extract sensitive data, or modify database contents.

### Fix Recommendation
Use parameterized queries with placeholders: models.sequelize.query('SELECT * FROM Products WHERE ((name LIKE ? OR description LIKE ?) AND deletedAt IS NULL) ORDER BY name', { replacements: [`%${criteria}%`, `%${criteria}%`], type: QueryTypes.SELECT })

---

## Finding 3: A01 - Broken Access Control

**File:** `routes/fileUpload.ts`  
**Line range:** 29-50  
**Confidence:** 0.92  

### Risk Summary
Path traversal vulnerability in ZIP file extraction. The code checks if the absolute path includes the current directory, but an attacker can use ZIP entries with path traversal sequences (e.g., '../../../etc/passwd') to write files outside the intended 'uploads/complaints/' directory. The path.resolve() check is insufficient because it resolves relative to the current working directory, not the uploads directory.

### Fix Recommendation
Validate that the resolved absolute path is within the target directory before extraction. Use: const targetDir = path.resolve('uploads/complaints/'); if (!absolutePath.startsWith(targetDir)) { entry.autodrain(); return; }. Additionally, sanitize fileName by removing path traversal sequences.

---

## Finding 4: A03 - Injection

**File:** `routes/fileUpload.ts`  
**Line range:** 1-10  
**Confidence:** 0.94  

### Risk Summary
XML External Entity (XXE) injection vulnerability. The code parses user-supplied XML files using libxmljs without disabling external entity resolution. The XML parser is configured with noent: true (process entity declarations), which enables XXE attacks. An attacker can upload a malicious XML file with XXE payloads to read arbitrary files from the server, perform SSRF attacks, or cause denial of service.

### Fix Recommendation
Disable external entity processing entirely. Use: libxml.parseXml(data, { noblanks: true, nocdata: true, noent: false, dtdload: false }). Remove the noent: true flag and consider using a hardened XML parser that disables external entities by default.

---

## Finding 5: A08 - Software & Data Integrity Failures

**File:** `routes/fileUpload.ts`  
**Line range:** 1-15  
**Confidence:** 0.92  

### Risk Summary
Untrusted file content is deserialized using yaml.load() without safe mode. An attacker can upload a malicious YAML file containing arbitrary code execution payloads (e.g., JavaScript objects that execute during deserialization). This bypasses the timeout protection since the payload executes during parsing.

### Fix Recommendation
Use yaml.safeLoad() instead of yaml.load(): vm.runInContext('JSON.stringify(yaml.safeLoad(data))', sandbox, { timeout: 2000 }). This prevents instantiation of arbitrary JavaScript objects during deserialization.

---

## Finding 6: A07 - Identification & Auth Failures

**File:** `routes/changePassword.ts`  
**Line range:** 12-16  
**Confidence:** 0.92  

### Risk Summary
Password parameters are extracted from the query string instead of the request body. Query parameters are logged in server logs, browser history, and proxy logs, exposing sensitive password data in plaintext. An attacker with access to logs can recover user passwords.

### Fix Recommendation
Move password extraction from query parameters to the request body: const currentPassword = req.body.current; const newPassword = req.body.new; const repeatPassword = req.body.repeat. Use POST or PUT method with JSON body instead of GET with query strings.

---

## Finding 7: A02 - Cryptographic Failures

**File:** `routes/resetPassword.ts`  
**Line range:** 29-31  
**Confidence:** 0.93  

### Risk Summary
The password is stored directly in the database without any hashing. The code calls user.update({ password: newPassword }) with plaintext password. An attacker with database access can read all user passwords in plaintext, and any data breach exposes credentials.

### Fix Recommendation
Hash the password before storing: use a bcrypt or argon2 library to hash newPassword before passing it to user.update(). Example: const hashedPassword = await bcrypt.hash(newPassword, 10); user.update({ password: hashedPassword })

---

## Finding 8: A01 - Broken Access Control

**File:** `routes/resetPassword.ts`  
**Line range:** 18-33  
**Confidence:** 0.89  

### Risk Summary
There is no authorization check verifying that the requesting user is resetting their own password. An attacker can reset any user's password by providing their email and guessing/brute-forcing the security answer, without any authentication of the requester's identity.

### Fix Recommendation
Add a check to ensure the user is authenticated and owns the email being reset: if (!req.user || req.user.email !== email) return res.status(403).send('Forbidden'). Alternatively, require the user to be logged in and only allow resetting their own account.

---

## Finding 9: A07 - Identification & Auth Failures

**File:** `routes/resetPassword.ts`  
**Line range:** 1-5  
**Confidence:** 0.82  

### Risk Summary
The password reset logic validates only a user ID and a security answer without rate limiting or account lockout mechanisms. An attacker can brute force the security answer across multiple attempts to reset any user's password.

### Fix Recommendation
Implement rate limiting on failed security question attempts (e.g., max 3 attempts per 15 minutes), account lockout after threshold, and CAPTCHA after 2 failed attempts. Log all reset attempts with timestamps.

---

## Finding 10: A01 - Broken Access Control

**File:** `routes/basket.ts`  
**Line range:** 14-16  
**Confidence:** 0.92  

### Risk Summary
The retrieveBasket endpoint retrieves a basket by ID from the URL parameter without verifying that the authenticated user owns the basket. An attacker can access any other user's basket by manipulating the ID parameter, bypassing the authorization check entirely.

### Fix Recommendation
Add an authorization check before returning the basket: verify that the authenticated user's basket ID (user.bid) matches the requested ID. Example: if (user?.bid !== parseInt(id, 10)) { return res.status(403).json({ error: 'Unauthorized' }); }

---

## Finding 11: A01 - Broken Access Control

**File:** `routes/order.ts`  
**Line range:** 31-32  
**Confidence:** 0.92  

### Risk Summary
The placeOrder function retrieves a basket by ID from req.params.id without verifying that the authenticated user owns that basket. An attacker can place orders for arbitrary baskets by manipulating the ID parameter, accessing and modifying other users' orders.

### Fix Recommendation
Add an authorization check after retrieving the basket to verify ownership: if (basket.UserId !== customer.id) { return res.status(403).json({ error: 'Forbidden' }); }

---

## Finding 12: A04 - Insecure Design

**File:** `routes/order.ts`  
**Line range:** 35-36  
**Confidence:** 0.85  

### Risk Summary
The order ID is generated using a hash of the customer email (first 4 chars) concatenated with a random hex string. This provides insufficient entropy and predictability—an attacker can potentially guess or forge order IDs for other customers since the email hash prefix greatly reduces the keyspace.

### Fix Recommendation
Generate order IDs using a cryptographically secure random method with sufficient entropy: const orderId = require('crypto').randomBytes(8).toString('hex'); Do not use user-controlled data like email in ID generation.

---

## Finding 13: A01 - Broken Access Control

**File:** `routes/order.ts`  
**Line range:** 38-39  
**Confidence:** 0.88  

### Risk Summary
The PDF file is written directly to the 'ftp/' directory using an order ID that is partially predictable. An attacker who can predict order IDs can access other users' order PDFs by guessing filenames, and the 'ftp/' directory may be web-accessible.

### Fix Recommendation
Store generated PDFs outside the web root with proper access controls. Serve PDFs only after verifying the requesting user owns the order. Use a UUID or cryptographically secure random ID instead of the predictable orderId.

---

## Finding 14: A01 - Broken Access Control

**File:** `routes/order.ts`  
**Line range:** 1-50  
**Confidence:** 0.92  

### Risk Summary
The code uses req.body.UserId directly without verifying that the authenticated user matches the UserId being processed. An attacker can modify req.body.UserId to perform wallet operations (debit/credit) on arbitrary user accounts, allowing theft of funds or unauthorized bonus points allocation.

### Fix Recommendation
Verify that the authenticated user's ID matches the UserId being processed before any wallet operations. Add a check like: if (req.user.id !== req.body.UserId) return res.status(403).send('Forbidden')

---

## Finding 15: A04 - Insecure Design

**File:** `routes/order.ts`  
**Line range:** 35-45  
**Confidence:** 0.88  

### Risk Summary
The wallet balance check and decrement operations lack transactional atomicity. Between the balance check (wallet.balance >= totalPrice) and the decrement operation, a race condition allows an attacker to place multiple simultaneous orders that each pass the balance check but collectively overdraft the wallet.

### Fix Recommendation
Use database transactions to atomically check and decrement the wallet balance in a single operation, preventing race conditions. Alternatively, use database-level constraints or row-level locking.

---

## Finding 16: A02 - Cryptographic Failures

**File:** `routes/order.ts`  
**Line range:** 17-27  
**Confidence:** 0.93  

### Risk Summary
Coupon validation uses client-supplied Base64-encoded data (req.body.couponData) without cryptographic verification. An attacker can forge arbitrary coupon codes and discount values by Base64-encoding malicious couponData, then base64 decoding and string splitting to extract coupon codes and dates that match hardcoded campaigns in the system.

### Fix Recommendation
Implement server-side coupon validation using cryptographic signatures (HMAC or digital signatures). Store coupon validation state server-side and do not trust client-supplied couponData. Example: Use a signed JWT or HMAC-SHA256 digest appended to the coupon data that can be verified server-side before applying discounts.

---

## Finding 17: A04 - Insecure Design

**File:** `routes/order.ts`  
**Line range:** 23-26  
**Confidence:** 0.82  

### Risk Summary
The coupon validation relies on a loose equality check (==) comparing couponDate with campaign.validOn. An attacker can bypass date validation by sending a couponDate that numerically equals a past campaign's validOn timestamp, allowing expired coupons to be applied. Server-side date validation is missing, trusting only client-supplied timestamps.

### Fix Recommendation
Replace loose equality with strict equality (===) and add server-side date validation: ensure the coupon is only valid within the current valid date window. Validate that the current server time falls within the coupon's active period on the backend.

---

## Finding 18: A02 - Cryptographic Failures

**File:** `lib/insecurity.ts`  
**Line range:** 19  
**Confidence:** 0.98  

### Risk Summary
A hardcoded RSA private key is embedded directly in source code. If this repository or compiled code is exposed, an attacker can forge any JWT tokens and impersonate any user in the system with complete access.

### Fix Recommendation
Load the private key from a secure environment variable or key management service instead of hardcoding it: const privateKey = process.env.JWT_PRIVATE_KEY

---

## Finding 19: A02 - Cryptographic Failures

**File:** `lib/insecurity.ts`  
**Line range:** 32  
**Confidence:** 0.92  

### Risk Summary
The hash function uses MD5, which is cryptographically broken. An attacker can easily generate collisions or precompute rainbow tables to crack password hashes or other hashed values.

### Fix Recommendation
Replace MD5 with a modern hashing algorithm: crypto.createHash('sha256').update(data).digest('hex') or use bcrypt/argon2 for password hashing.

---

## Finding 20: A02 - Cryptographic Failures

**File:** `lib/insecurity.ts`  
**Line range:** 33  
**Confidence:** 0.94  

### Risk Summary
The HMAC function uses a hardcoded static key 'pa4qacea4VK9t9nGv7yZtwmj' embedded in source code. If exposed, attackers can forge valid HMACs and bypass message integrity checks.

### Fix Recommendation
Load the HMAC key from a secure environment variable: crypto.createHmac('sha256', process.env.HMAC_SECRET || '').update(data).digest('hex')

---

## Finding 21: A01 - Broken Access Control

**File:** `lib/insecurity.ts`  
**Line range:** 48-56  
**Confidence:** 0.89  

### Risk Summary
The isRedirectAllowed function uses string.includes() to validate redirect URLs, which allows bypass through URL prefix matching. An attacker can redirect to a malicious URL like 'https://attacker.com?url=https://github.com/juice-shop/juice-shop' since the allowlist entry is a substring match.

### Fix Recommendation
Use exact URL matching or parse the URL properly: redirectAllowlist.has(url) with a Set of exact URLs, or validate the hostname separately using new URL(url).hostname

---

## Finding 22: A01 - Broken Access Control

**File:** `lib/insecurity.ts`  
**Line range:** 14-18  
**Confidence:** 0.82  

### Risk Summary
The appendUserId middleware directly accesses authenticatedUsers.tokenMap without validating that the token exists or belongs to the current request. If a token is not in the map or has been invalidated, req.body.UserId may be left undefined, allowing subsequent authorization checks to be bypassed.

### Fix Recommendation
Add explicit validation: const user = authenticatedUsers.tokenMap[utils.jwtFrom(req)]; if (!user || !user.data || !user.data.id) { return res.status(401).json({...}); } req.body.UserId = user.data.id;

---

## Finding 23: A07 - Identification & Auth Failures

**File:** `lib/insecurity.ts`  
**Line range:** 21-31  
**Confidence:** 0.85  

### Risk Summary
The updateAuthenticatedUsers middleware uses jwt.verify with a callback but does not validate the decoded token structure before storing it, and always calls next() regardless of verification result. This allows unauthenticated or malformed requests to proceed.

### Fix Recommendation
Check verification result and token structure: jwt.verify(token, publicKey, (err, decoded) => { if (err === null && decoded && decoded.data && decoded.data.id) { authenticatedUsers.put(token, decoded); next(); } else { return res.status(401).json({...}); } });

---

## Finding 24: A05 - Security Misconfiguration

**File:** `frontend/src/app/login/login.component.ts`  
**Line range:** 58-59  
**Confidence:** 0.72  

### Risk Summary
Hardcoded Google OAuth client ID is exposed in the source code. This credential can be extracted from the compiled JavaScript and potentially misused, though impact is limited since OAuth client IDs are semi-public by design.

### Fix Recommendation
Move the clientId to a backend configuration endpoint or environment-specific configuration file rather than hardcoding in client-side source code.

---

## Finding 25: A07 - Identification & Auth Failures

**File:** `frontend/src/app/login/login.component.ts`  
**Line range:** 61-62  
**Confidence:** 0.93  

### Risk Summary
Hardcoded test credentials (testingUsername and testingPassword) are exposed in the production source code. An attacker can extract these credentials and use them to gain unauthorized access to the application as a test user account.

### Fix Recommendation
Remove hardcoded test credentials from the source code. If test accounts are needed, manage them through a secure configuration system that is not deployed to production. Use environment-specific builds to exclude test credentials from production deployments.

---

## Finding 26: A01 - Broken Access Control

**File:** `frontend/src/app/login/login.component.ts`  
**Line range:** 20-22  
**Confidence:** 0.78  

### Risk Summary
The redirectUri is used directly in a URL construction for OAuth without sufficient validation. An attacker could manipulate the authorizedRedirect response to inject a malicious URI, causing the user's browser to redirect to an attacker-controlled domain and potentially stealing the OAuth token.

### Fix Recommendation
Validate that redirectUri matches a strict whitelist of expected domains before use. Implement URL parsing and validation: const url = new URL(this.redirectUri); if (!['trusted-domain.com'].includes(url.hostname)) { throw new Error('Invalid redirect'); }

---

## Finding 27: A02 - Cryptographic Failures

**File:** `frontend/src/app/login/login.component.ts`  
**Line range:** 42-43  
**Confidence:** 0.89  

### Risk Summary
Authentication tokens are stored in localStorage, which is vulnerable to XSS attacks. If an attacker injects malicious JavaScript, they can steal the token from localStorage. Additionally, storing sensitive tokens in localStorage provides no protection against XSS.

### Fix Recommendation
Store authentication tokens in httpOnly, secure cookies instead of localStorage. Remove the localStorage.setItem('token', ...) call and rely only on the secure cookie set by this.cookieService.put() with httpOnly flag enabled on the server.

---

## Finding 28: A02 - Cryptographic Failures

**File:** `frontend/src/app/login/login.component.ts`  
**Line range:** 47  
**Confidence:** 0.85  

### Risk Summary
A temporary OAuth token is stored in localStorage (totp_tmp_token) during 2FA flow. This temporary token is vulnerable to XSS theft and should not be stored in localStorage where JavaScript can access it.

### Fix Recommendation
Store the temporary token in a secure httpOnly cookie or in memory only, not in localStorage. If a cookie is used, ensure the httpOnly and secure flags are set server-side.

---

## Finding 29: A02 - Cryptographic Failures

**File:** `frontend/src/app/login/login.component.ts`  
**Line range:** 58  
**Confidence:** 0.75  

### Risk Summary
The remember-me feature stores the user's email address in localStorage in plaintext. An attacker with access to the device or via XSS can retrieve and misuse the email address.

### Fix Recommendation
Do not store email addresses in localStorage. If remember-me functionality is required, use a secure, signed token stored in an httpOnly cookie instead.

---

## Finding 30: A07 - Identification & Auth Failures

**File:** `models/user.ts`  
**Line range:** 56-59  
**Confidence:** 0.78  

### Risk Summary
The password hashing function is called without verifying password strength or enforcing complexity requirements. An attacker can register with weak passwords like '123' or 'password', making brute-force attacks feasible. The code comment references 'weakPasswordChallenge', suggesting this is a known vulnerability.

### Fix Recommendation
Implement password strength validation before hashing. Enforce minimum length (12+ characters), complexity requirements (uppercase, lowercase, numbers, symbols), and reject common weak passwords: if (!isStrongPassword(clearTextPassword)) throw new Error('Password too weak'); this.setDataValue('password', security.hash(clearTextPassword))

---

## Finding 31: A01 - Broken Access Control

**File:** `models/user.ts`  
**Line range:** 1-20  
**Confidence:** 0.82  

### Risk Summary
The role field accepts values from a hardcoded allowlist via the `isIn` validator, but there is no authorization check preventing a user from setting their own role to 'admin' during account creation or update. An attacker can directly manipulate the role assignment to grant themselves administrative privileges.

### Fix Recommendation
Remove the ability for users to set their own role. Role assignment should only be performed by authorized administrators through a separate, protected endpoint with proper authorization checks. Use a custom validator that enforces role immutability or restrict role changes to admin-only operations.

---
