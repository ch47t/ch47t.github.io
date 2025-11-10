---
title: Web Security Fundamentals
subtitle: A comprehensive guide to understanding web vulnerabilities, security testing tools, and essential security concepts
author: Boogeyman
date: 2025-11-5
categories: [Web Security, Pentesting, Burp Suite, Vulnerabilities]
tags: [web-security, ssrf, idor, lfi, rce, burp-suite, hydra, reconnaissance]
layout: post
pin: false
image:
  path: /assets/img/posts/web-security-fundamentals/image1.png
  alt: Web Security Fundamentals - Overview
---

{% include embed.html %}

## Learning Roadmap

- **Web Foundations**  
  Client-server architecture, HTTP protocols, and how the web works at a fundamental level.

- **Security Testing**  
  Burp Suite tools and techniques for discovering and analyzing web vulnerabilities.

- **Vulnerabilities**  
  Common attack vectors like SSRF and other exploitable security flaws in web applications.

## The Client-Server Model

Web communication follows a simple but critical architecture where clients (browsers) send requests to servers, which respond with data. Understanding this foundation is essential for identifying security weaknesses.

**Programming Languages**  
Backend systems use Python, PHP, Node.js, Java, and many others to process requests.

**HTTP Versions**  
HTTP/1.1, HTTP/2, and HTTP/3 each have different characteristics affecting performance and security.

## Internet Ports and Network Services

Ports are logical endpoints on a server that identify specific services. Common ports include:

| Port | Service   |
|------|-----------|
| 80   | HTTP      |
| 443  | HTTPS     |
| 22   | SSH       |
| 3306 | MySQL     |

Understanding port mapping helps identify exposed services and potential attack surfaces during reconnaissance.

![Nmap example]({% link /assets/img/posts/web-security-fundamentals/image2.png %})  
<figcaption>Nmap scanning open ports</figcaption>

## HTTP Requests and Responses

HTTP is the protocol that powers the web. Every interaction between client and server follows a request-response cycle. Requests contain methods (GET, POST, etc.), headers, and optional bodies, while responses include status codes and content.

![HTTP Request/Response]({% link /assets/img/posts/web-security-fundamentals/image3.png %})  
<figcaption>HTTP request-response cycle</figcaption>

## Session Management and HTTP Cookies

HTTP is stateless—each request is independent. Servers use cookies to maintain session state, storing user information like authentication tokens. Understanding cookie mechanics is critical for identifying session hijacking and other session-based vulnerabilities.

![Cookies example]({% link /assets/img/posts/web-security-fundamentals/image4.png %})  
<figcaption>Cookie inspection in dev tools</figcaption>

## Scope Discovery and Reconnaissance

Before testing for vulnerabilities, security professionals must map the target application's attack surface through systematic enumeration.

### 01 Subdomain Enumeration
gobuster dns -d target_domain -w wordlist  
Layer deeper by brute-forcing subdomains of subdomains.

### 02 Service Enumeration
nmap -sV -p- target_ip

### 03 Directory Brute-Forcing
gobuster dir -u https://target_url -w wordlist -x php,html,txt

![Recon tools]({% link /assets/img/posts/web-security-fundamentals/image5.png %})  
<figcaption>Gobuster and Nmap in action</figcaption>

## Setting Up Your Security Testing Proxy

A proxy intercepts traffic between your browser and web servers, allowing you to inspect, modify, and replay requests—essential for security testing.

Browser ↔ Proxy ↔ Server

The proxy sits in the middle of the communication, capturing all traffic so you can verify both frontend and backend behavior.

![Proxy flow]({% link /assets/img/posts/web-security-fundamentals/image6.png %})  
<figcaption>Proxy interception diagram</figcaption>

## Burp Suite: Your Security Testing Arsenal

**Community vs. Professional**  
Community Edition is free and includes core features. Professional Edition adds automated scanning, advanced tools, and 24/7 support.

**Essential Tools**

- **Repeater**: Manually craft and send requests
- **Intruder**: Automate attacks with payload variations
- **Decoder**: Encode/decode data formats
- And more: Scanner, Comparer, Collaborator

![Burp Suite interface]({% link /assets/img/posts/web-security-fundamentals/image7.png %})  
<figcaption>Burp Suite dashboard</figcaption>

## Authentication Brute-Force

### Hydra
hydra -l jeremy -P /usr/share/wordlists/rockyou.txt 127.0.0.1 http-post-form \
"/labs/a0x01.php:username=^USER^&password=^PASS^:F=Your username or password was incorrect" \
-t 16 -o hydra-found.txt

### Burp Suite Intruder
Use for clustered payload attacks in labs.

![Hydra/Burp auth]({% link /assets/img/posts/web-security-fundamentals/image8.png %})  
<figcaption>Brute-force attack results</figcaption>

## INSECURE DIRECT OBJECT REFERENCES (IDOR)

IDORs happen when users can access resources that do not belong to them by directly referencing the object ID, object number, or filename.

**Example:**  
https://example.com/messages?user_id=1234

![IDOR example]({% link /assets/img/posts/web-security-fundamentals/image9.png %})  
<figcaption>IDOR vulnerability demo</figcaption>

## Path Traversal & LFI & RFI

From Local File Inclusion (LFI) or Remote File Inclusion (RFI) to Remote Code Execution (RCE).

../../../../etc/passwd  
?file=php://filter/convert.base64-encode/resource=index.php

![Path traversal payloads]({% link /assets/img/posts/web-security-fundamentals/image10.png %})  
<figcaption>LFI payload examples</figcaption>

## Server-Side Request Forgery (SSRF)

SSRF occurs when a web application makes requests to external URLs without proper validation. An attacker can manipulate the URL parameter to access internal services, bypassing network security controls.

**Vulnerable Example**  
https://example.com/feed.php?url=externalsite.com/feed  
Attacker changes to `url=http://localhost/admin` or internal IPs.

**Mitigation:**
- Validate and whitelist allowed URLs
- Block internal IP ranges (`127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Disable unnecessary protocols
- Implement network segmentation

![SSRF example]({% link /assets/img/posts/web-security-fundamentals/image11.png %})  
<figcaption>SSRF internal access</figcaption>

## Remote Code Execution (RCE)

Hands-on labs recommended.

![RCE lab]({% link /assets/img/posts/web-security-fundamentals/image12.png %})  
<figcaption>RCE exploitation lab</figcaption>

![RCE payload]({% link /assets/img/posts/web-security-fundamentals/image13.png %})  
<figcaption>Successful RCE payload</figcaption>

---

**Happy hacking (ethically)!**  
Remember: Only test systems you have explicit permission to penetrate.

{% if page.comments %}
<div class="comments">
  {% include disqus.html %}
</div>
{% endif %}
