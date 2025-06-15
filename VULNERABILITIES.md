## 🔐 Selected Vulnerability Analysis (20 of 154)

<details>
<summary><strong>1. Apache PHP-CGI Remote Code Execution</strong> (CVE-2024-4577)</summary>

- **Severity**: Critical
- **Affected Service**: PHP (Apache Integration)
- **Affected Port**: N/A
- **Description**: The installed version of PHP allows arbitrary code execution via crafted CGI requests. This vulnerability can be used to gain remote shell access.
- **Suggested Fix**:
  - Update PHP to the latest patched version
  - Disable CGI execution if not needed
  - Restrict access to script directories

</details>

---

<details>
<summary><strong>2. Samba Remote Code Execution</strong> (CVE-2007-2447)</summary>

- **Severity**: High
- **Affected Service**: SMB (Samba)
- **Affected Port**: 445
- **Description**: Command injection vulnerability in Samba allows remote attackers to execute code as root via crafted requests to shared folders.
- **Suggested Fix**:
  - Upgrade Samba to a secure version
  - Disable guest access
  - Isolate Samba behind internal firewalls

</details>

---

<details>
<summary><strong>3. vsftpd Backdoor</strong> (CVE-2011-2523)</summary>

- **Severity**: Critical
- **Affected Service**: FTP (vsftpd)
- **Affected Port**: 21
- **Description**: A malicious version of vsftpd allows attackers to gain shell access by logging in with a crafted username.
- **Suggested Fix**:
  - Replace vsftpd with a trusted version
  - Restrict anonymous access
  - Monitor authentication logs

</details>

---

<details>
<summary><strong>4. Weak SSL Keys due to Debian RNG Flaw</strong> (CVE-2008-3280)</summary>

- **Severity**: Critical
- **Affected Service**: OpenSSL / OpenSSH
- **Affected Port**: 22 / HTTPS Ports
- **Description**: Weak SSL keys generated due to a flawed Debian RNG allow predictable key generation, making brute force attacks viable.
- **Suggested Fix**:
  - Regenerate all affected keys
  - Upgrade to patched OpenSSL versions
  - Reissue and revoke old certificates

</details>

---

<details>
<summary><strong>5. NFS Shares World Readable</strong> (CVE-2002-1836)</summary>

- **Severity**: High
- **Affected Service**: NFS
- **Affected Port**: 2049 TCP/UDP
- **Description**: NFS shares are exported without access restrictions, allowing unauthorized mounts.
- **Suggested Fix**:
  - Configure NFS exports with IP or hostname restrictions
  - Use firewalls to limit NFS access

</details>

---

<details>
<summary><strong>6. VNC Server Running with Weak Password</strong> (N/A) </summary>

- **Severity**: Critical
- **Affected Service**: VNC (Virtual Network Computing)
- **Affected Port**: 5900
- **Description**: VNC server allows access with weak password ("password"), enabling remote compromise.
- **Suggested Fix**:
  - Use strong passwords
  - Disable unused VNC services
  - Implement network-layer authentication

</details>

<details>
<summary><strong>7. UnrealIRCd Backdoor Detection </strong> (CVE-2010-2075) </summary>

- **Severity**: Critical
- **Affected Service**: IRC (Internet Relay Chat)
- **Affected Port**: N/A
- **Description**: Version of UnrealIRC was downloaded from a mirror site. This version contains a Trojan Horse which can be used by an attacker to execute abritrary code from a remote machine
- **Suggested Fix**:
  - Uninstall UnrealIRC and verify the MD5/SHA before redownloading it from the official website.

</details>
<details>
<summary><strong>8. DNS server is vulnerable to cache snooping </strong> (N/A) </summary>

- **Severity**: Medium
- **Affected Service**: DNS server
- **Affected Port**: 53
- **Description**: The remote DNS server responds to queries for third-party domains that do not have the recursion bit set. This may allow a remote attacker to determine which domains have recently been resolved via this name server, and therefore which hosts have been recently visited. An might find this information useful.
- **Suggested Fix**:
  - Contact DNS software vendor for a fix

</details>
<details>
<summary><strong>9. Browsable web directories </strong> (N/A) </summary>

- **Severity**: Medium
- **Affected Service**: Web directories
- **Affected Port**:
- **Description**: Multiple Nessus plugins identified directories on the web server that are browsable.
- ## **Suggested Fix**:
  - Use access restrictions to ensure confidentiality on sensitive files/folders.

</details>
<details>
<summary><strong>10. SSL certificate expiry </strong> (N/A) </summary>

- **Severity**: Medium
- **Affected Service**: Browsing the web
- **Affected Port**: 80/443
- **Description**: This plugin checks expiry dates of certificates associated with SSL- enabled services on the target and reports whether any have already expired. Expired SSL certificates cannot be verified
- **Suggested Fix**:
  - Purchase or generate a new SSL certificate to replace the existing one.

</details>
<details>
<summary><strong>11. ISC BIND Service Downgrade / Reflected DoS  </strong> (CVE-2020-8616) </summary>

- **Severity**: High
- **Affected Service**: DNS/BIND
- **Affected Port**: 53
- **Description**: According to its self-reported version, the instance of ISC BIND 9 running on the remote name server is affected by performance downgrade and Reflected DoS vulnerabilities. This is due to BIND DNS not sufficiently limiting the number fetches which may be performed while processing a referral response.

An unauthenticated, remote attacker can exploit this to cause degrade the service of the recursive server or to use the affected server as a reflector in a reflection attack.

- **Suggested Fix**:
  - Upgrade to the ISC BIND version referenced in the vendor advisory.

</details>
<details>
<summary><strong>12. Canonical Ubuntu Linux SEol (security end of life)  </strong> (N/A) </summary>

- **Severity**: Critical
- **Affected Service**: Canonical
- **Affected Port**: N/A
- **Description**: According to its version, Canonical Ubuntu Linux is 8.04.x. It is, therefore, no longer maintained by its vendor or provider. Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may contain security vulnerabilities. Canonical Ubuntu Linux 8.04x is also open source, making it even more susceptible to an attack.
- **Suggested Fix**:
  - Upgrade to a version of Canonical Ubuntu Linux that is currently supported.

</details>
<details>
<summary><strong>13. SSH weak algorithms </strong> (N/A) </summary>

- **Severity**: Medium
- **Affected Service**: SSH
- **Affected Port**: 22
- **Description**: Nessus has detected that the remote SSH server is configured to use the Arcfour stream cipher or no cipher at all. RFC 4253 advises against using Arcfour due to an issue with weak keys.
- **Suggested Fix**:
  - Contact the vendor or consult product documentation to remove the weak ciphers.

</details>
<details>
<summary><strong>14. Web Server Allows Password Auto-Completion </strong> (N/A) </summary>

- **Severity**: Low
- **Affected Service**: Web servers
- **Affected Port**: 80/443
- **Description**: The remote web server contains at least one HTML form field that has an input of type 'password' where 'autocomplete' is not set to 'off'. While this does not represent a risk to this web server per se, it does mean that users who use the affected forms may have their credentials saved in their browsers, which could in turn lead to a loss of confidentiality if any of them use a shared host or if their machine is compromised at some point.
- **Suggested Fix**:
  - Turn 'autocomplete' off on password fields in the affected web servers

</details>
<details>
<summary><strong>15. Web Server Uses Basic Authentication Without HTTPS </strong> (CWE 319) </summary>

- **Severity**: Low
- **Affected Service**: HTTP traffic
- **Affected Port**: 80
- **Description**: The remote web server contains web pages that are protected by 'Basic' authentication over cleartext. An attacker eavesdropping the traffic might obtain logins and passwords of valid users.
- **Suggested Fix**:
  - Make sure that HTTP authentication is transmitted over HTTPS.

</details>
<details>
<summary><strong>16. SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam) </strong> (CVE-2015-4000) </summary>

- **Severity**: Low
- **Affected Service**: TLS
- **Affected Port**: N/A
- **Description**: The remote host allows SSL/TLS connections with one or more Diffie-Hellman moduli less than or equal to 1024 bits. Through cryptanalysis, a third party may be able to find the shared secret in a short amount of time. This may allow an attacker to recover the plaintext or potentially violate the integrity of connections.
- **Suggested Fix**:
  - Reconfigure the service to use a unique Diffie-Hellman moduli of 2048 bits or greater.

</details>
<details>
<summary><strong>17. rsh Service Detection </strong> (CVE-1999-0651) </summary>

- **Severity**: High
- **Affected Service**: RSH
- **Affected Port**: 514
- **Description**: The rsh service is running on the remote host. This service is vulnerable since data is passed between the rsh client and server in cleartext. A man-in-the-middle attacker can exploit this to sniff logins and passwords. Also, it may allow poorly authenticated logins without passwords.
- **Suggested Fix**:
  - Comment out the 'rsh' line in /etc/inetd.conf and restart the inetd process. Alternatively, disable this service and use SSH instead.

</details>
<details>
<summary><strong>18. It is possible to retrieve file backups from the remote web server. </strong> (N/A) </summary>

- **Severity**: Medium
- **Affected Service**: Backup file server
- **Affected Port**: N/A
- **Description**: By appending various suffixes (ie: .old, .bak, ~, etc...) to the names of various files on the remote host, it seems possible to retrieve their contents, which may result in disclosure of sensitive information.
- **Suggested Fix**:

  - Ensure the files do not contain any sensitive information, such as credentials to connect to a database, and delete or protect those files that should not be accessible.
  </details>
  <details>
  <summary><strong>19. PHP expose_php Information Disclosure </strong> (N/A) </summary>

- **Severity**: Medium
- **Affected Service**: PHP
- **Affected Port**:
- **Description**: The PHP install on the remote server is configured in a way that allows disclosure of potentially sensitive information to an attacker through a special URL. Such a URL triggers an Easter egg built into PHP itself.
- **Suggested Fix**:
  - In the PHP configuration file, php.ini, set the value for 'expose_php' to 'Off' to disable this behavior. Restart the web server daemon to put this change into effect.

</details>
<details>
<summary><strong>20. ICMP Timestamp Request Remote Date Disclosure </strong> (CVE-1999-0524) </summary>

- **Severity**: Medium
- **Affected Service**: ICMP
- **Affected Port**:
- **Description**: The remote host answers to an ICMP timestamp request. This allows an attacker to know the date that is set on the targeted machine, which may assist an unauthenticated, remote attacker in defeating time-based authentication protocols.
- **Suggested Fix**:
  - Filter out the ICMP timestamp requests (13), and the outgoing ICMP timestamp replies (14).

</details>
