  # Cyber Threat Intelligence


So, throughout my career, one of the questions I get asked the most is about CTI stuff. I've been thinking for a while about creating some content on this, but every time I start writing, it gets way too long because CTI is a really complex topic, and there’s no magic formula to be a great Threat Hunting pro.

I can say that working with Threat Hunting means you’re always, always studying and improving every second. Sometimes, right before going to sleep, I start questioning certain incidents, wondering if I could have done something differently. Or I catch myself thinking about proactive Threat Hunting — imagining how I might spot a threat that no one’s found yet. I start piecing together scenarios in my head like a puzzle and reflecting on them.

Doing Hunting means knowing you have to stay updated and keep learning to walk side by side with threats. But honestly, in my experience, you rarely are exactly side by side. If you’re just a few steps behind the threat, that already makes you a great professional. Studying threats is key so you don’t fall too far behind the attacker.

The closer you are to the threats, the clearer you’ll see them. Let me give you an example of a sophisticated espionage threat that hit security devices, specifically Cisco ASA firewalls.

These devices protect government and corporate networks, acting like major security barriers. But in 2023, a campaign called ArcaneDoor showed how state-sponsored hackers exploited two zero-day vulnerabilities in these firewalls to breach multiple government networks worldwide. These attackers managed to run malicious code directly on the security devices, spy on network traffic, steal data, and maintain persistent access not just with software tricks, but also by implanting a tiny hardware component—a small chip—right on the firewalls’ circuit boards. This allowed their control to survive even after system reboots and updates.

<img width="870" height="643" alt="{EA4BCFC2-FDD4-4788-A8A0-19902A89B078}" src="https://github.com/user-attachments/assets/bfcac78f-1cd1-4202-a2f5-0ba1306ccec9" />


This example reinforces a vital lesson for anyone working in Threat Hunting: the closer you are to the threats, the faster and more proactively you can identify and remediate attacks of this level of sophistication. Understanding espionage techniques, vulnerabilities, and behaviors allows you to anticipate actions and significantly reduce the impact on protected environments. Staying just one step behind the threat — instead of many — is what makes a good professional stand out.

Here are some questions I like to ask myself when investigating incidents to collect and analyze information:

## Who?
Name, username, or ID
Responsible party — for example, after identifying the attack behavior, try to understand if it belongs to a known threat group

## When?
Date/time the threat was identified, and after analysis, try to find the start date. Sometimes you discover it today, but the exploitation has been going on for years.
Were there other correlated events from the start date until you identified it?

## Where?
Identifying the internal host is super important because there are many variables here. Sometimes you might be investigating a host that’s part of a production line, which are often highly vulnerable due to legacy environments. Or maybe it’s a host where employees have free access and everyone uses it, opening the door to possibilities like insider threats. Or it could even be a host used for pentesting. Knowing the host helps you understand its importance. In a compromised environment, one of the things you want is to isolate the host so the attacker loses access and you can do forensic analysis. But if it’s a critical host, you might not be able to isolate it. So knowing what kind of host it is and where it is helps you understand how far your actions can go — how deep into the host and infrastructure you can respond.

Identifying the attacker’s host is also important — for example, knowing their domain, IP, and location.

## Why?
What’s the motivation? (Financial gain, espionage, hacktivism)

Is this asset valuable to the attacker? Understanding if the asset is valuable is very important. You need to know what information is inside that asset and its importance within the environment. I’ve worked on cases where analyzing the attacker’s behavior made it clear that the device wasn’t that important, and the attacker had other devices under control in the environment. So they were just burning one device, not caring if they lost access to it because it wasn’t valuable — and the attacker knew this too. Spotting this is important because based on the attacker’s behavior, you can tell if they’re just sacrificing that device to gather info.

## How?
What attack vector was used? (Malware, phishing, RDP)

What technique was applied? (Lateral movement? Data exfiltration?)

Alright, now let’s say you have an incident but you don’t know the user who did it. A common thing in attacks is privilege escalation. So, you check the incident and see that everything is being done by the root user. One of the most used EDRs worldwide is Falcon. Let’s say we’re in an environment using Falcon — I like to start with a query to check the last logons on the host.

## Logons
```text
#event_simpleName=UserLogon
| UserUUID:=UserSid | UserUUID:=UID
| groupBy([aid], function=([selectFromMax(field="@timestamp", include=[ComputerName, UserUUID, UserName, LogonType, @timestamp])]))
| $falcon/helper:enrich(field=LogonType)
| aid=~match(file="aid_master_main.csv", column=[aid])
```

So, after analyzing the logons and collecting the data, I like to check out the command lines next

## Host Linux - Last commands removing other tools from path (+clean)
```text
#event_simpleName="*Process*"
| aid=?aid
| CommandLine=?CommandLine
| (ImageFileName!=*CrowdStrike*) AND (ImageFileName!=*guardicore*) //Paths to exclude from filter
| UserName!=zabbix* //User to exclude from filter
| table([@timestamp, UserName, ImageFileName, CommandLine, SHA256HashData, #event_simpleName], limit=1000)
```

So, after analyzing the command lines, we’ll often have a bunch of information. Now it’s time to filter and separate what’s relevant from what’s not. That’s why in my query, sometimes I exclude certain users — like in the example above where I filtered out the user “zabbix.” But you have to keep in mind that this is just to keep the filter cleaner.

What guarantees that the “zabbix” user hasn’t been compromised? So, you really need to be careful when applying filters


Another thing I like to do is validate the communications of the host I’m investigating with external environments. For that, I use the following query

## Connections to External Addresses
```text
#event_simpleName=NetworkConnect*
| aid=?aid
| RemotePort=?RemotePort
| !cidr(RemoteAddressIP4, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32"])
| table([ComputerName, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort, @timestamp], limit=1000)
```

So, let’s say I have the IP in hand — the malicious actor’s IP — and I have the executed commands. Now I want to see all the actions from that IP on the target host, so I’ll use one of the queries below

## Activities of an IP on the Host
```text
#event_simpleName=Network* AND RemoteAddressIP4=
| aid=?aid
```
//OR
```text
#event_simpleName=Network* AND RemoteIP=*
| aid=?aid
| table(fields = [ComputerName, #event_simpleName, ContextBaseFileName, RemoteIP, RemotePort, LocalIP, LocalPort, ConnectionDirection, @timestamp])
```

Alright, so I gave a simple example above to show you how to start your investigation on a case. But every case has its own level of complexity — some are more complex, others less. Some can be solved in just a few hours, while others might take days or even months. And your race is always against the clock.

In this repository, I’ve included a folder with some CS Falcon queries that might be useful for your investigations. [Querys Falcon](FALCON-queries.md)

Here’s also a repository that contains over 170 tools for querying IPs, hashes, IOCs, groups, and other helpers for your investigations — like tools to identify APT groups, blockchain tracking, and more... 🔗 [Repository with auxiliary tools](https://github.com/sculptormoon/blue-team-auxiliary)

🔗 [Check out this repository about Threat Intelligence](https://github.com/sculptormoon/Threat-Intelligence)

Well, on my profile, there are several repositories that might be useful for your investigations, including ones focused on malware analysis and others.

This repository gives a small overview of CTI because, like I mentioned earlier, CTI is a complex subject. To be a good CTI professional, you need to master various skills like reverse engineering, forensic techniques, deep knowledge of attack methodologies, and understanding behavioral aspects related to attacks and espionage.

So, I hope this repository helps guide you on your journey to becoming a great CTI analyst.

## License

This repository is licensed under the MIT License. The license covers the content of this repository, which consists of links and related information. See the [LICENSE](LICENSE) file for more details.

## Author
### Lucas Benites.

## Contact
If you have any questions or need more information, feel free to contact me through my GitHub profile [perfil GitHub](https://github.com/sculptormoon).


