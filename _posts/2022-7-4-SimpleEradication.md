---
title: "Simple Eradication PowerShell Script"
date: "2022-7-4"
layout: single
---


![](https://raw.githubusercontent.com/Aboalfadl/aboalfadl.github.io/main/Images/Cleaning.png)

### Tool URL: [Click Here](https://github.com/Aboalfadl/aboalfadl.github.io/releases/download/Edarication.PowerShell/SimpleEradication.zip)

What is this script about?
		- While doing DFIR in a previous incident and finished the essential incident response steps. The APT targeting this entity only uses one persistence technique: setting the malicious files in the startup folder (T1547.001). I also found that there are other locations in every compromised system for the copied malicious file for other malicious use.
		Unfortunately, the entity has no EDR, so I created a PowerShell script to do the eradication step after blocking all the IOCs from the firewall and then pushing it using the AD to all the machines.
		- The script doesn't discover the malicious behavior or detect malicious files. Instead, the PowerShell script works by feeding it the malicious processes names to kill and the malicious files MD5 hashes to clean.
		- So, once feeding the In-Script (Process Names, MD5 Files) as instructed inside the script, it will now find the malicious process names, kill them, and clean the system from the malicious files.
		-  This is a quick solution I did to eradicate systems from malware, and maybe it will help the community, so happy hunting.		

Tool Brief:

- Once the tool started it will show some network information, and then find the machine users to get every user path and calculate the hashes, as appeared in the screenshot below: 

![](https://raw.githubusercontent.com/Aboalfadl/aboalfadl.github.io/main/Images/HashesCount.png)

- Then the tool will compare the machine hashes with the provided hashes to find the malicious ones if any, as the below screenshot: 

![](https://raw.githubusercontent.com/Aboalfadl/aboalfadl.github.io/main/Images/ProcessKill.png)

- If any malicious processes found or hashes , will be killed and cleaned.

### To use this cleaner:
- open PowerShell as administrator.
- navigate to the current folder of the cleaner.
- type .\Eradication.ps1
- Script will run and after it finish a transcript will be available on the same directory of the script.
- Cleaner will kill all malicious processes and delete/clean the system from the malicious files.
- If there are any issues please contact me: dark@aboalfadl.com
  

```Thanks. Happy Hunting.```
