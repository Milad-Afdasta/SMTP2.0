
# SMTP 2.0: A Next-Generation Protocol for Secure, Verified, and Efficient Email

## **Table of Contents**
1. [Introduction](#introduction)  
2. [Scope of the Problem: Spam, Spoofing, and Resource Drain](#scope-of-the-problem)  
   2.1 [High Volume of Illegitimate Email](#21-high-volume-of-illegitimate-email)  
   2.2 [Impact on Bandwidth, Processing, and Memory](#22-impact-on-bandwidth-processing-and-memory)  
   2.3 [Benefits of Adopting SMTP 2.0](#23-benefits-of-adopting-smtp-20)  
3. [Proposed Solution: SMTP 2.0 Core Concepts](#proposed-solution)  
   3.1 [Certificate-Based Mutual Authentication](#31-certificate-based-mutual-authentication)  
   3.2 [DNSSEC-Enforced Certificate Discovery](#32-dnssec-enforced-certificate-discovery)  
   3.3 [Enhanced End-User Indicators](#33-enhanced-end-user-indicators)  
   3.4 [Compatibility with Existing Anti-Spam Solutions](#34-compatibility-with-existing-anti-spam-solutions)  
4. [Technical Implementation and Details](#technical-implementation)  
   4.1 [Protocol Flow](#41-protocol-flow)  
   4.2 [Changes to Mail Server Configuration](#42-changes-to-mail-server-configuration)  
   4.3 [Example Configuration Snippet](#43-example-configuration-snippet)  
5. [Example: Spoof Prevention](#example-spoof-prevention)  
   5.1 [Legacy SMTP Spoof](#51-legacy-smtp-spoof)  
   5.2 [SMTP 2.0 Spoof Attempt](#52-smtp-20-spoof-attempt)  
6. [Multi-Phase Adoption Approach](#multi-phase-adoption)  
7. [Summary](#summary)  
8. [SMTP 2.0 Specification Improvement Proposals](#smtp-20-specification-improvement-proposals)  
   8.1 [Email Forwarding and Distribution Systems](#81-email-forwarding-and-distribution-systems)  
   8.2 [Legacy System Integration](#82-legacy-system-integration)  
   8.3 [Certificate Management](#83-certificate-management)  
   8.4 [Performance Optimization](#84-performance-optimization)  
   8.5 [Security Enhancements](#85-security-enhancements)  
   8.6 [Small Organization Support](#86-small-organization-support)  
   8.7 [Metrics and Monitoring](#87-metrics-and-monitoring)  
   8.8 [Documentation and Standards](#88-documentation-and-standards)  
   8.9 [Future Proofing](#89-future-proofing)  
9. [Five Key Points and Final Notes](#five-key-points-and-final-notes)  
10. [Contributor](#contributor)  
11. [Open Source MIT License](#open-source-mit-license)  

---

<a name="introduction"></a>
## **1. Introduction**

Email remains one of the most important communication channels worldwide—used by individuals, small businesses, and large enterprises alike. Unfortunately, as the protocol and infrastructure around email have evolved over decades, security was not always at the forefront. Traditional email protocols allow for spoofing, phishing, and spam to thrive, costing billions of dollars in losses annually.

**SMTP 2.0** is a proposed upgrade to the current Simple Mail Transfer Protocol (SMTP) ecosystem, designed to dramatically reduce domain spoofing, provide cryptographic verification of senders, and simplify the trust model for both service providers and end users. By leveraging robust certificate-based authentication and (ideally) DNSSEC-protected DNS records, SMTP 2.0 aims to ensure:

1. **Sender Authenticity**: Messages cannot be sent unless the sender’s server can present a valid certificate proving domain ownership.  
2. **In-Transit Encryption**: Mandatory TLS (Transport Layer Security) with strict enforcement ensures data confidentiality and integrity.  
3. **User Trust Indicator**: Email clients (MUAs) can display a “verified domain” indicator, similar to web browsers’ lock icons.

With **minimal changes** to existing mail server infrastructure—especially where TLS is already in use—providers can implement SMTP 2.0 and dramatically reduce spam, phishing, and unauthorized spoofing of their domains.

---

<a name="scope-of-the-problem"></a>
## **2. Scope of the Problem: Spam, Spoofing, and Resource Drain**

<a name="21-high-volume-of-illegitimate-email"></a>
### **2.1 High Volume of Illegitimate Email**

Numerous industry reports estimate that a **significant portion of global email traffic—often cited between 45% to 60%—is spam, phishing attempts, or otherwise malicious.** Within this enormous volume of unwanted traffic:

- A large subset is **domain spoofing** (e.g., forging “From: ceo@bank.com”).  
- Another subset is general spam from domains that have no legitimate reputation or are newly registered (and possibly can still obtain valid certificates).

Service providers spend substantial time and resources processing, filtering, and quarantining these messages. Even robust spam filters can be bypassed, leading to fraud, phishing, and malware attacks.

<a name="22-impact-on-bandwidth-processing-and-memory"></a>
### **2.2 Impact on Bandwidth, Processing, and Memory**

- **Bandwidth**: Each spam or spoof email consumes bandwidth during SMTP handshakes, data transmission, and subsequent rejections/filters.  
- **Processing Power**: Spam filters, antivirus engines, and content scanning tools require CPU cycles to inspect each incoming message.  
- **Memory and Storage**: Mail queues, logs, and quarantines store large volumes of unwanted messages, adding complexity and cost to operations.

<a name="23-benefits-of-adopting-smtp-20"></a>
### **2.3 Benefits of Adopting SMTP 2.0**

By adopting **SMTP 2.0** (with mandatory certificate-based authentication and recommended DNSSEC), the ecosystem can:

- **Eliminate or Vastly Reduce Spoofed Domain Emails**: Attackers cannot easily forge a certificate for a domain they do not own.  
- **Reduce Overall Spam Volumes**: Especially spam that relies on impersonating trusted domains. Content filters will still be needed to handle bulk spam from newly acquired domains, but domain spoofing scams become infeasible.  
- **Lower Operational Costs**: Fewer spoofed messages means reduced CPU usage, disk I/O, and memory usage for email scanning engines—**potentially saving significant resources** allocated to spam handling (actual numbers vary by provider).  
- **Increase Trust & User Confidence**: Clear indications that an email is from a verified domain helps users identify legitimate communications, reducing phishing success rates.

---

<a name="proposed-solution"></a>
## **3. Proposed Solution: SMTP 2.0 Core Concepts**

<a name="31-certificate-based-mutual-authentication"></a>
### **3.1 Certificate-Based Mutual Authentication**

1. **Server Certificate**:  
   - Each domain’s mail server must present a valid X.509 certificate (e.g., from Let’s Encrypt or other reputable CAs), proving it is authorized to send mail on behalf of that domain.  
   - Receiving mail servers verify this certificate against their trusted CA store, ensuring domain ownership is legitimate.

2. **Client Certificate**:  
   - In a true mutual TLS scenario, the sending server also verifies the certificate of the receiving server.  
   - This ensures both parties know they are communicating with the legitimate endpoints.

<a name="32-dnssec-enforced-certificate-discovery"></a>
### **3.2 DNSSEC-Enforced Certificate Discovery (Recommended to be Mandatory)**

1. **DNS Records**:  
   - A new or extended DNS record could indicate the domain’s mail certificate or a URL to fetch certificate chains (similar to MTA-STS or DANE).  
   - **DNSSEC** ensures these DNS records are signed, preventing attackers from poisoning or redirecting DNS lookups.

2. **Mandatory DNSSEC** (Ideal Future State):  
   - Enforces cryptographic validation of DNS responses.  
   - Eliminates a significant vector for man-in-the-middle (MITM) or DNS hijacking attacks.  
   - Acknowledging that global DNSSEC adoption is still limited, SMTP 2.0 may operate in a transitional state where DNSSEC is strongly encouraged before eventually becoming mandatory.

<a name="33-enhanced-end-user-indicators"></a>
### **3.3 Enhanced End-User Indicators**

- Email clients can present a “Verified by <CA>” badge or a lock icon next to the sender’s domain.  
- Users can quickly see whether the email truly originates from “@bank.com” or is a spoof.  
- These indicators rely on *metadata* from the receiving server, which can add a header (e.g., `X-SMTP2-Verified: <certificate info>`) for consumption by the mail client (MUA).

<a name="34-compatibility-with-existing-anti-spam-solutions"></a>
### **3.4 Compatibility with Existing Anti-Spam Solutions**

- **SPF, DKIM, DMARC** remain complementary, especially for content or policy enforcement.  
- Existing heuristic spam filters also remain important for unsolicited email from valid-but-misleading domains (e.g., random new .info or .xyz domains).  
- SMTP 2.0 aims to drastically reduce spoofing from well-known domains, thereby lowering the load on spam filters and diminishing user confusion.

---

<a name="technical-implementation"></a>
## **4. Technical Implementation and Details**

<a name="41-protocol-flow"></a>
### **4.1 Protocol Flow**

1. **DNS Lookup (with DNSSEC if available)**  
   - Sending MTA checks for the receiving domain’s mail server record (`MX` or similar).  
   - Optionally fetches a new record (e.g., `_smtp2._tcp.recipient.com`) providing certificate details or a pointer to the CA chain.  
   - Validates these DNS records with DNSSEC (strongly recommended).

2. **Mutual TLS Handshake**  
   - The sending server connects to the receiving server over a strictly enforced TLS session (on port 25 or a newly dedicated port).  
   - **Receiving server presents its certificate**, validated by the sending server’s trust store.  
   - **Sending server presents its own certificate**, validated by the receiving server.  
   - If either side fails certificate validation, the handshake terminates—or falls back to a legacy/trusted-low-level state if partial compatibility is configured (see [8.2 Legacy System Integration](#82-legacy-system-integration)).

3. **Authenticated SMTP Session**  
   - SMTP commands (HELO, MAIL FROM, RCPT TO, DATA, etc.) occur over an encrypted channel.  
   - The receiving server logs the verified domain of the sender (from the certificate).

4. **Delivery to Mailbox**  
   - Once stored, the message includes meta-information that it was “Validated by <CA>.”  
   - The end-user’s mail client can read this and show a secure indicator or “verified domain” badge.

<a name="42-changes-to-mail-server-configuration"></a>
### **4.2 Changes to Mail Server Configuration**

1. **Certificates & Keys**  
   - Each MTA needs an X.509 certificate for the domain it serves, plus the private key.  
   - Admins can automate certificate issuance/renewal via ACME (e.g., Let’s Encrypt).  

2. **Enforce Strict TLS**  
   - Replace opportunistic “STARTTLS” with mandatory TLS on either port 25 or a dedicated secure port.  
   - Fallback or “hybrid” modes may exist during an adoption phase where legacy SMTP connections can still be accepted but flagged as insecure.

3. **DNSSEC Support**  
   - Mail servers should verify DNSSEC signatures (library-level or OS-level configuration).  
   - In future phases, DNSSEC will be a hard requirement for certificate discovery.

<a name="43-example-configuration-snippet"></a>
### **4.3 Example Configuration Snippet**

*(Using hypothetical Postfix-style syntax for illustration; these options may not exist exactly in today’s Postfix. They represent proposed directives.)*

```ini
# Enforce mutual TLS with certificate validation
smtp_tls_security_level = encrypt
smtp_tls_enforce_cert_validation = yes
smtp_tls_enforce_hostnames = yes
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt

# Our domain’s certificate and key
smtp_tls_cert_file = /etc/ssl/certs/mail.example.com.crt
smtp_tls_key_file  = /etc/ssl/private/mail.example.com.key

# (Hypothetical) DNSSEC and certificate discovery settings
smtp_dnssec_enforce = yes
smtp_tls_require_peer_cert_match = yes
smtp_dns_cert_lookup = yes

# Additional fallback or hybrid configuration
smtp_legacy_fallback = permissive
smtp_log_legacy_connections = yes
```

---

<a name="example-spoof-prevention"></a>
## **5. Example: Spoof Prevention**

<a name="51-legacy-smtp-spoof"></a>
### **5.1 Legacy SMTP Spoof**

- An attacker sets up a random server claiming to be `ceo@bank.com`.  
- Without strict SPF/DKIM/DMARC or if these are misconfigured, many servers might accept the email.  
- Users see a “From: ceo@bank.com” and may be fooled.

<a name="52-smtp-20-spoof-attempt"></a>
### **5.2 SMTP 2.0 Spoof Attempt**

- Attacker again tries to claim `ceo@bank.com`.  
- Connection fails during the TLS handshake because the attacker cannot present a valid certificate for `bank.com`.  
- Spoofed email never reaches the user, effectively blocking the attack.  
- If a fallback mechanism is configured (e.g., partial legacy acceptance), the receiving server can mark the message as unverified or refuse it altogether, depending on policy.

---

<a name="multi-phase-adoption"></a>
## **6. Multi-Phase Adoption Approach**

A roadmap is critical to transitioning millions of domains without breaking email flow overnight.

1. **Phase 1: Voluntary Adoption & Standards Drafting**  
   - **Publish Internet-Draft**: Formulate a new or updated RFC that outlines SMTP 2.0 requirements (mutual TLS, DNSSEC usage, certificate discovery).  
   - **Open Source Implementations**: Provide patches or forks for popular MTAs (e.g., Exim, Postfix, OpenSMTPD) that add SMTP 2.0 compatibility.  
   - **Early Adopter Incentives**: Encourage major providers (Google, Microsoft, Apple) to run pilot programs.

2. **Phase 2: Strong Recommendations & Partial Enforcement**  
   - Large providers begin **enforcing certificate validation** for inbound mail from domains that publish “SMTP 2.0 readiness” in DNS.  
   - Email clients start displaying a “Verified Domain” badge if the message is delivered via SMTP 2.0.  
   - DNSSEC is **strongly recommended**, with warnings or reduced trust levels for domains not signing their zones.  
   - A fallback path (hybrid) may exist so legacy servers can still connect, though marked at a lower trust level.

3. **Phase 3: Universal Enforcement & Mandatory DNSSEC**  
   - In collaboration with the IETF and major providers, set a date to deprecate acceptance of email from servers not presenting valid certificates.  
   - DNSSEC becomes mandatory for the discovery process. Non-DNSSEC domains are treated as untrusted.  
   - By this stage, the majority of email traffic is protected by robust mutual TLS with cryptographically validated domain certificates.

---

<a name="summary"></a>
## **7. Summary**

- **Email Security Today**: Riddled with spoofing, spam, and optional security layers that are inconsistently deployed.  
- **SMTP 2.0**: A straightforward yet powerful enhancement requiring mutual certificate authentication and (ideally) DNSSEC-protected certificate discovery.  
- **Benefits**:  
  - Virtually eliminate domain spoofing for adopters.  
  - Reduce spam load and resource consumption.  
  - Provide visible trust indicators to end users.  
- **Adoption Path**: Begins with open-source prototypes, a new or revised IETF RFC, and major provider buy-in. Over time, it transitions from optional to mandatory, ensuring global trust and drastically lowering the risk of phishing scams.

---

<a name="smtp-20-specification-improvement-proposals"></a>
## **8. SMTP 2.0 Specification Improvement Proposals**

Below are additional proposals to enhance and refine SMTP 2.0. They address real-world deployment challenges and ensure future-proofing.

<a name="81-email-forwarding-and-distribution-systems"></a>
### **8.1 Email Forwarding and Distribution Systems**

#### **Forwarding Mechanism**
- **Certificate Delegation System**: Define how authorized forwarders can obtain or be delegated a certificate from the original domain owner.  
- **"Forward-Chain" Header**: Introduce a header that tracks each forwarding hop, allowing receiving servers and MUAs to validate the path of a forwarded message.  
- **Forwarder Signing**: Forwarding servers sign messages with their own certificates but attach a cryptographic “chain” proving authenticity from the original domain.

#### **Mailing Lists and Distribution**
- **Mailing List Authenticity**: Define how mailing list software can maintain the authenticity of messages (e.g., re-signing with the list’s certificate while preserving original sender info).  
- **Message Modification Indicators**: Standardize how mailing lists indicate they have modified subject lines, headers, or footers.  
- **Subscriber Verification**: Allow subscribers to verify that changes came from a legitimate mailing list rather than a malicious intermediary.

<a name="82-legacy-system-integration"></a>
### **8.2 Legacy System Integration**

#### **Transition Protocol**
- **Backward Compatibility Layer**: Clearly define a “reduced trust” handshake for connections from legacy SMTP servers without certificates.  
- **Graduated Authentication**: Implement partial verification that logs or tags unverified connections but does not necessarily reject them.  
- **Migration Timelines**: Establish recommended timeframes for phasing out legacy acceptance.

#### **Hybrid Mode Operation**
- **Mixed Environments**: Specify how servers operate with both SMTP 2.0 and legacy SMTP.  
- **Fallback Mechanisms**: If certificate validation fails, servers can revert to legacy SMTP with clear warnings/logs.  
- **Metrics Collection**: Track metrics (volume, deliverability, spam rates) for legacy vs. SMTP 2.0 traffic to inform policy decisions.

<a name="83-certificate-management"></a>
### **8.3 Certificate Management**

#### **Lifecycle Management**
- **Standard Lifetimes**: Define typical certificate validity (e.g., 90 days for ACME-based certs).  
- **Rotation Procedures**: Require automated certificate rotation to reduce risk of expired certificates.  
- **Emergency Replacement**: Clearly define protocols for immediate revocation and reissuance in case of key compromise.

#### **Compromise Handling**
- **Revocation Procedures**: Mandate real-time revocation checks (OCSP or CRLs) so invalid certificates are promptly rejected.  
- **Revocation Timeframes**: Encourage rapid CA response times (e.g., within hours for critical revocations).  
- **Recovery Steps**: Outline how domain owners can re-establish trust quickly if a key compromise occurs.

#### **Domain Hierarchy**
- **Subdomain & Wildcard Certificates**: Define how subdomains can either share a wildcard certificate or have unique certificates.  
- **Parent-Child Validation**: Ensure a consistent chain of trust from parent domain to subdomain.  
- **Delegation for Multi-Level Domains**: Clarify how large enterprises or resellers can delegate certificate authority to sub-organizations.

<a name="84-performance-optimization"></a>
### **8.4 Performance Optimization**

#### **High-Volume Processing**
- **Connection Pooling**: Recommend that MTAs pool TLS connections to reduce overhead of frequent handshakes.  
- **Certificate Caching**: Cache validated certificates to avoid repetitive validations.  
- **Performance Benchmarks**: Provide guidelines and reference implementations showing minimal overhead with mutual TLS.

#### **Resource Management**
- **Memory & CPU Usage**: Offer best practices for concurrency, queue management, and thread pooling.  
- **Connection Handling Under Load**: Define how servers handle spikes in inbound or outbound connections without dropping TLS verification.  
- **Quality of Service (QoS)**: Allow prioritization of verified SMTP 2.0 traffic over unverified legacy connections.

<a name="85-security-enhancements"></a>
### **8.5 Security Enhancements**

#### **Quantum Resistance**
- **Post-Quantum Cryptography**: Outline how SMTP 2.0 can migrate to PQ-safe algorithms in certificates and TLS ciphers.  
- **Upgrade Paths**: Define a version negotiation for transitioning from current RSA/ECDSA to post-quantum signatures.  
- **Minimum Key Length**: Periodically update recommended key sizes to remain future-proof.

#### **Certificate Authority Security**
- **Multi-CA Validation**: Encourage cross-checking certificate chains or pinning to multiple trusted CAs to mitigate single-CA compromise.  
- **CA Compromise Mitigation**: Provide an emergency response framework if a major CA is compromised.  
- **CA Auditing & Monitoring**: Require third-party audits of CAs issuing SMTP 2.0 certificates.

#### **Failure Mode Handling**
- **Graceful Degradation**: If a server cannot validate a certificate, provide a clear error or fallback.  
- **Error Reporting**: Standardize how servers log and report certificate-related errors.  
- **Recovery Procedures**: Document how to restore normal operation after system-wide or partial outages.

<a name="86-small-organization-support"></a>
### **8.6 Small Organization Support**

#### **Certificate Management Assistance**
- **Automated Certificate Management**: Define protocols (e.g., ACME) for seamless certificate acquisition and renewal without extensive admin overhead.  
- **Simplified Acquisition**: Encourage free or low-cost certificate options (e.g., Let’s Encrypt).  
- **Managed Service Providers**: Provide guidelines for MSPs to handle certificates on behalf of customers.

#### **Resource Considerations**
- **Minimum Hardware**: Outline resource requirements for smaller servers (RAM, CPU).  
- **Lightweight Implementation**: Offer simplified installations or packages that enable SMTP 2.0 with minimal configuration steps.  
- **Cost-Effective Deployment**: Suggest hosting providers or containerized solutions that reduce overhead.

<a name="87-metrics-and-monitoring"></a>
### **8.7 Metrics and Monitoring**

#### **Performance Tracking**
- **Standard Metrics**: Define which KPIs to track (e.g., handshake success rate, certificate validation time, spam detection rates).  
- **Monitoring Requirements**: Encourage real-time or near-real-time dashboards for mail flow.  
- **Reporting Protocols**: Share consistent data formats (JSON, etc.) for interoperability.

#### **Security Monitoring**
- **Event Logging**: Log certificate expiration checks, revocations, or failures.  
- **Incident Detection**: Provide hooks for SIEM (Security Information and Event Management) systems to detect anomalies.  
- **Threat Intelligence Sharing**: Outline how providers can share blacklists, compromised certificate alerts, or suspicious domain data.

<a name="88-documentation-and-standards"></a>
### **8.8 Documentation and Standards**

#### **Implementation Guide**
- **Detailed Documentation**: Publish official guides for configuring popular MTAs (Postfix, Exim, OpenSMTPD, Microsoft Exchange).  
- **Configuration Examples**: Offer step-by-step example configs, including DNSSEC and certificate setup.  
- **Troubleshooting**: Provide common error scenarios and solutions.

#### **Conformance Testing**
- **Test Suites**: Create open-source test harnesses that verify MTA compliance with SMTP 2.0 specs.  
- **Certification Requirements**: Define an official compliance program or badge for fully conformant implementations.  
- **Compliance Verification**: Offer self-service or third-party tools to validate server configurations.

<a name="89-future-proofing"></a>
### **8.9 Future Proofing**

#### **Protocol Evolution**
- **Version Negotiation**: Define how servers can gracefully announce and negotiate SMTP 2.0 or future 2.x/3.0 versions.  
- **Extension Points**: Provide a modular approach for new features like advanced metadata, new cryptographic suites, or specialized routing.  
- **Upgrade Paths**: Make it simple for the IETF or community to extend the protocol without another major fork.

#### **Ecosystem Development**
- **API Requirements**: For third-party tool integration, define robust APIs or plugin architectures (e.g., antivirus, spam filters, threat intelligence).  
- **Plugin Architecture**: Enable additional checks (e.g., advanced content scanning) without breaking the core protocol.  
- **Guidelines for Growth**: Encourage an open ecosystem where vendors can innovate on top of the core SMTP 2.0 standards.

---

<a name="five-key-points-and-final-notes"></a>
## **9. Five Key Points and Final Notes**

In line with previous feedback, here are five key areas that deserve emphasis and careful handling:

1. **Clarify the Scope of Spam Reduction**  
   - SMTP 2.0 primarily eliminates *spoofing* of established domains. Spammers using newly registered or obscure domains with valid certificates can still send unwanted mail, so content filters remain relevant.

2. **Transition & Fallback**  
   - Gradual migration is crucial. A fallback or partial verification mode can log and mark unverified connections rather than rejecting them outright at the start. This ensures legacy systems do not break immediately.

3. **Certificate Discovery & DNSSEC**  
   - Leverage or extend existing standards like DANE (TLSA records) or MTA-STS. Emphasize DNSSEC strongly to prevent tampering in certificate discovery. Acknowledge that DNSSEC adoption is incomplete and plan for a transitional state.

4. **Technical Nuances**  
   - Define recommended ciphers, TLS versions (preferably TLS 1.3), and potential post-quantum transitions.  
   - Provide guidelines for how MUAs display verified senders (e.g., adding a header or an out-of-band verification mechanism).

5. **Adoption Complexity**  
   - Millions of domains, from small personal servers to large enterprises, require different levels of support.  
   - Proposed improvement proposals (Sections [8.1](#81-email-forwarding-and-distribution-systems) through [8.9](#89-future-proofing)) address forwarders, mailing lists, performance concerns, certificate revocation, and more, creating a robust ecosystem approach.

By tackling these five points alongside the proposed improvements, SMTP 2.0 stands on a stronger foundation for real-world adoption and long-term success.

---

<a name="contributor"></a>
## **10. Contributor**

This document was contributed by **Milad Afdasta**.  
Additional improvements and expansions provided by community feedback.

---

<a name="open-source-mit-license"></a>
## **11. Open Source MIT License**

```
MIT License

2025 Milad Afdasta

Permission is hereby granted, free of charge, to any person obtaining a copy
of this document (the "Document") and associated documentation files (the "Document"), 
to deal in the Document without restriction, including without limitation 
the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Document, and to permit persons to whom the Document 
is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included 
in all copies or substantial portions of the Document.

THE DOCUMENT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
DOCUMENT OR THE USE OR OTHER DEALINGS IN THE DOCUMENT.
```

**End of Document**
```
