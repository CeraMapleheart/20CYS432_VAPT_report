## Wi-Fi Router Penetration Testing Report

### Roll No.: CB.EN.U4CYS21061 - ROSHNI.V
### 1. **Introduction**
   - **Objective**: The objective of this penetration test is to identify vulnerabilities in the home Wi-Fi router, assess the security measures in place, and recommend improvements to mitigate risks.
   - **Scope**: The test focuses on wireless network security, including encryption protocols, default configurations, and access controls.

### 2. **Requirements**
   - **Hardware**:
     - Home Wi-Fi router (model: TP-Link C5 4-Antenna Gigabit Router)
   - **Software Tools**:
     - Nmap for network scanning - https://nmap.org/download.html
     - Aircrack-ng for Wi-Fi password cracking - https://www.aircrack-ng.org/downloads.html
     - Wireshark for traffic analysis - https://www.wireshark.org/download.html
     - Burp Suite for web application testing - https://portswigger.net/burp/releases/community/latest

### 3. **Methodology**
   - The testing follows a structured approach based on established frameworks such as NIST SP 800-115 (https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf) and OWASP Testing Guide (https://github.com/OWASP/wstg/tree/master/document).

#### **Step 1: Information Gathering**
   - Identify the router model and firmware version.
   - Research known vulnerabilities associated with that model.
   - Gather details about the network setup (SSID, encryption type).

#### **Step 2: Network Scanning**
   - Use Nmap to scan the network for active devices and open ports.
     ```bash
     nmap -sP 192.168.1.0/24
     ```
   - Identify services running on the router and check for default credentials.

#### **Step 3: Wi-Fi Security Testing**
   - Assess the strength of the Wi-Fi password using Aircrack-ng.
     ```bash
     airodump-ng wlan0
     ```
   - Capture WPA/WPA2 handshake packets.
     ```bash
     airodump-ng --bssid [BSSID] --channel [channel] --write [file] wlan0
     ```
   - Attempt to crack the captured handshake using a wordlist.
     ```bash
     aircrack-ng [file].cap -w [wordlist]
     ```

#### **Step 4: Traffic Analysis**
   - Capture packets using Wireshark to analyze unencrypted traffic.
     ```bash
     wireshark
     ```
   - Look for sensitive information being transmitted without encryption.

#### **Step 5: Configuration Assessment**
   - Review router settings for security best practices:
     - Disable WPS (Wi-Fi Protected Setup).
     - Change default SSID and passwords.
     - Enable MAC address filtering if applicable.

### 4. **Results Analysis**
![image](https://github.com/user-attachments/assets/7bfb75cc-3eea-4c8e-ab4b-1f013cedfb69)
- All identified vulnerabilities with detailed descriptions:
  
| Vulnerability                | Description                                      | Evidence                                           | Risk Level |
|------------------------------|--------------------------------------------------|---------------------------------------------------|------------|
| Default Credentials           | Router uses default admin credentials            | Screenshot of login page showing default credentials | High       |
| Weak WPA2 Password           | Password easily crackable via dictionary attack  | Command output showing successful password crack    | High       |
| Unencrypted Traffic          | Sensitive data transmitted without encryption    | Wireshark capture showing plaintext data           | Medium     |



### 5. **Mitigation Strategies**
- **Change Default Credentials**: 
  - Change all default passwords for your Wi-Fi network and router to strong, unique passwords. This prevents unauthorized access.
  
- **Implement Complex WPA2 Password**: 
  - Use a complex WPA2 password that includes uppercase letters, lowercase letters, numbers, and symbols. This enhances security against brute-force attacks.

- **Disable WPS**: 
  - Disable WPS (Wi-Fi Protected Setup) as it can be exploited by attackers within range through brute-force methods.

- **Enable Strong Firewall Settings**: 
  - Configure the router's firewall settings to allow only legitimate traffic while blocking unauthorized access attempts.

- **Regular Firmware Updates**: 
  - Keep the router’s firmware updated to ensure any known vulnerabilities are patched. Enable automatic updates if available.

### 6. **Conclusion**
- The assessment revealed critical vulnerabilities in the home Wi-Fi router that could be exploited by attackers to gain unauthorized access or intercept sensitive data. Regularly updating security settings and conducting assessments are crucial in maintaining network security and protecting against potential threats.

### 7. **Appendices**
- **Tools Used with Configurations**:
  - Nmap version 7.95, configured with default settings.
  - Aircrack-ng version 1.7, using standard wordlists from https://github.com/berzerk0/Probable-Wordlists/blob/master/Real-Passwords/Top12Thousand-probable-v2.txt.
  
- **Full Command Outputs from Tests Conducted**:
  
```bash
# Nmap Scan Output
nmap scan report for [router IP]
Host is up (0.0010s latency).
Not shown: 999 closed ports
PORT      STATE SERVICE
80/tcp  open http

# Aircrack-ng Output
aircrack-ng output:
[...]
KEY FOUND! [password]
```


Citations:
[1] https://info.teledynamics.com/blog/common-wi-fi-security-threats-and-how-to-mitigate-them
[2] https://www.infosecinstitute.com/resources/network-security-101/wireless-attacks-and-mitigation/
[3] https://www.cyber.gc.ca/en/guidance/routers-cyber-security-best-practices-itsap80019
[4] https://purplesec.us/learn/wireless-network-attack/
[5] https://www.cisa.gov/news-events/news/securing-wireless-networks
[6] https://www.globalsign.com/en/blog/12-best-practices-wireless-network-security
[7] https://wyebot.com/blogs/wifi-multicast-benefits-problems-and-mitigation-strategies/
[8] https://www.binary.house/files/en/wifi_penetration_testing.pdf
