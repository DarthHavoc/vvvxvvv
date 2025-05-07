Obfuscation & Encoding: I've noticed some obfuscated strings and base64 commands popping up, which might be an attempt to hide malicious activity. This is definitely something we should keep an eye on.

Suspicious Script Execution: There have been a few unusual script executions from hidden or uncommon directories like /tmp and /var. This could indicate someone trying to run scripts in a way that avoids detection.

File Downloads: There are a few instances where commands like curl or wget were used to download files. This could be someone pulling down malicious files or payloads from the internet.

Privilege Escalation: I’ve seen some attempts to escalate privileges, using sudo, changing file ownership, or modifying permissions. This is often a tactic used to gain higher access, so it's a red flag.

Security Bypass: There are a few logs indicating that system security features are being disabled, like SIP on macOS or SELinux on Linux. Adversaries may be trying to weaken system defenses to maintain access.

Persistence Mechanisms: I’ve noticed some cron jobs being created and changes in launchd configurations on macOS. This could indicate someone trying to establish persistence on the systems.


index=cisnet-ws sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode IN (4104, 4103)
("export-certificate" OR "export-pfxcertificate" OR ("certutil" AND "-exportPFX"))
| eval messagecut = replace(Message, "[\n\r]+", " ")
| rex field=messagecut "Export-(?:Certificate|PfxCertificate)\s+-FilePath\s+(?<FilePath>\S+)\s+-Cert\s+(?<CertVar>\$\S+)"
| rex field=messagecut "certutil.*-exportPFX\s+(?<CertCN>\S+)"
| rex field=messagecut "Get-ChildItem\s+['\"]?Cert:\\\\[^\\]+\\\\[^\\]+\\\\(?<CertSubject>[^\"']+)"
| eval _time=strftime(_time, "%Y/%m/%d %T")
| table _time, host, User, title, FilePath, CertVar, CertSubject, CertCN, messagecut
| sort _time


| rex field=messagecut "Get-ChildItem\s+[\"']?Cert:\\\\[^\\]+\\\\[^\\]+\\\\(?<CertSubject>[^\\"']+)"


index=cisnet-ws sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode IN (4104, 4103)
("export-certificate" OR "export-pfxcertificate" OR ("certutil" AND "-exportPFX"))
| eval messagecut = replace(Message, "[\n\r]+", " ")
| rex field=messagecut "Export-(?:Certificate|PfxCertificate)\\s+-FilePath\\s+(?<FilePath>\\S+)\\s+-Cert\\s+(?<CertVar>\\$\\S+)"
| rex field=messagecut "certutil.*-exportPFX\\s+(?<CertCN>\\S+)"
| rex field=messagecut "Get-ChildItem\\s+[\"']?Cert:\\\\[^\\\\]+\\\\[^\\\\]+\\\\(?<CertSubject>[^\"']+)"
| eval _time=strftime(_time, "%Y/%m/%d %T")
| table _time, host, User, title, FilePath, CertVar, CertSubject, CertCN, messagecut
| sort _time


                                                            index=cisnet-ws sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
("export-certificate" OR "export-pfxcertificate" OR "Get-ChildItem" OR "ThumbPrint")
| eval messagecut = replace(Message, "[\n\r]+", " ")
| rex field=messagecut "Creating Scriptblock text \(\d of \d\): (?<command_executed>.*?)ScriptBlock ID:"
| rex field=messagecut "ThumbPrint\s+-eq\s+\"(?<CertThumbprint>[a-fA-F0-9]{40})\""
| rex field=messagecut "\$cert\s*=\s*Get-ChildItem\s+-Path\s+Cert:\\\\[^\\\\]+\\\\[^\\\\]+\\\\(?<DirectThumbprint>[a-fA-F0-9]{40})"
| rex field=messagecut "Subject\s+-like\s+\"\\*CN=(?<CertCN>[^\"]+)\\*\""
| rex field=messagecut "\$cert\.*?\.Subject\s*=\s*\"(?<CertSubject>[^\"]+)\""
| eval CertThumbprint=coalesce(CertThumbprint, DirectThumbprint)
| table _time, host, User, CertThumbprint, CertSubject, CertCN, command_executed, messagecut
| sort -_time



Behavioral + Frequency Filtering
Detecting rare/local enumeration attempts.
Situations where anomalous behavior matters more than raw volume.

index=* sourcetype=Sysmon OR sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational"
(CommandLine IN ("net localgroup*", "*Get-LocalGroup*", "*Get-LocalGroupMember*"))
| where NOT (User IN ("NT AUTHORITY\\SYSTEM", "DOMAIN\\svc_*", "DOMAIN\\admin*", "LOCAL\\Administrator"))
| where NOT (ParentImage IN ("C:\\Program Files\\CyberArk\\*", "*ServiceNow*", "*C:\\Windows\\System32\\Perfmon.exe"))
| eval suspicious=if(like(CommandLine, "%localgroup%") OR like(CommandLine, "%Get-LocalGroup%"), 1, 0)
| stats count by _time, User, Computer, CommandLine, ParentImage, ParentCommandLine
| where count < 5  // adjust threshold for frequency



Detection 1: Local Group Enumeration via Net/PowerShell/WMI

Purpose: Catch enumeration of local group names/memberships using common methods: net localgroup, PowerShell cmdlets, and WMI queries.

Search Template:

index=cisnet-ws sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" OR source="*Sysmon*"
(CommandLine IN ("*net localgroup*", "*get-localgroup*", "*Get-LocalGroupMember*", "*wmic group get name*", "*Get-WMIObject*Win32_Group*"))
NOT (User IN ("NT AUTHORITY\\SYSTEM", "*-admin*", "*svc*", "*nessus*", "*monitor*"))
NOT (CommandLine IN ("*ServiceNow Users*", "*Performance Monitor Users*"))
NOT (ParentCommandLine IN ("*CyberArk*"))
| eval User=coalesce(User, Account_Name)
| table _time dest User CommandLine ParentCommandLine

Optional Enhancements:

    Add detection for script block logging with EventCode=4104 if enabled.

    Include Get-CimInstance -Class Win32_Group (modern WMI replacement).

🔹 Detection 2: Suspicious File Drop for Admin Priv Check (e.g., win.dat)

Purpose: Detect malware behavior where adversaries create specific files like win.dat to check admin rights or signal privilege escalation.

Search Template:

index=cisnet-ws sourcetype=*Filesystem*
file_name="win.dat"
| eval root_drive=mvindex(split(file_path, "\\"), 0)
| eval path_depth=mvcount(split(file_path, "\\"))
| where LIKE(root_drive, "C:") AND path_depth <= 2
| table _time dest file_name file_path user process_name process_id

Why Keep This?
This detection is less noisy but high value when triggered. It aligns with behaviors used by RATs like NjRAT.
🔹 

Detection 3: Obfuscated or Advanced PowerShell Enumeration (Script Block Logging)

Purpose: Catch obfuscated or encoded group enumeration commands using script block logging (very powerful if enabled).

Search Template:

index=cisnet-ws sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
ScriptBlockText IN ("*get-localgroup*", "*Get-LocalGroupMember*", "*Get-WmiObject*Win32_Group*")
NOT (ScriptBlockText IN ("*ServiceNow*", "*Performance Monitor*", "*monitoring scripts*"))
| table _time dest User ScriptBlockText


