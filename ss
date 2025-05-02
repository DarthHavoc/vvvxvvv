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

