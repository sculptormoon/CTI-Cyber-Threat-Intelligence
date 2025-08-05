## Host Linux - Last commands removing other tools from path (+clean)
```text
#event_simpleName="*Process*"
| aid=?aid
| CommandLine=?CommandLine
| (ImageFileName!=*CrowdStrike*) AND (ImageFileName!=*guardicore*) //Paths to exclude from filter
| UserName!=zabbix* //User to exclude from filter
| table([@timestamp, UserName, ImageFileName, CommandLine, SHA256HashData, #event_simpleName], limit=1000)
```


## Host Windows - Last commands
```text
#event_simpleName=*Process*
OR #event_simpleName=CommandHistory
| aid=?aid
| UserName=*
| FileName=*
| CommandLine=*
| table([@timestamp, #event_simpleName, UserName, ParentBaseFileName, FileName, CommandLine, ImageFileName, SHA256HashData, ComputerName], limit=10000)
| rename(FileName, as="Main Process") | rename(CommandLine, as="Command Line") | rename(ImageFileName, as="FilePath") | rename(SHA256HashData, as="File Hash") | rename(ParentBaseFileName, as="Related Process") | rename(UserName, as="User")
```


## DNS Requests Made by a Host
```text
#event_simpleName=DnsRequest
| aid=?aid
| groupBy([ComputerName, DomainName], limit=max)
```


## Connections to External Addresses
```text
#event_simpleName=NetworkConnect*
| aid=?aid
| RemotePort=?RemotePort
| !cidr(RemoteAddressIP4, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32"])
| table([ComputerName, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort, @timestamp], limit=1000)
```


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


## Bringing All Activities of an IP in the Environment
```text
#event_simpleName=NetworkConnect* AND RemoteAddressIP4=
| table([ComputerName,LocalAddressIP4,LocalPort,RemoteAddressIP4,RemotePort], limit=1000)
```
//OR
```text
#event_simpleName=Network* AND RemoteIP=
| groupBy([ComputerName], function=collect([RemoteIP, #event_simpleName], limit=1000))
```


## Search for Hash Across Entire Environment
```text
SHA256HashData=
| groupBy([ComputerName, ImageFileName])
```
//OR
```text
SHA256HashData=
| count(aid)
```


## Search for DNS Requests Related to a Specific Process in Entire Environment
```text
#event_simpleName=DnsRequest
| aid=?aid
| join({#event_simpleName=ProcessRollup2 aid=?aid ImageFileName=/PROGRAMNAME\.exe/i}, key=TargetProcessId, field=ContextProcessId, include=[CommandLine, ImageFileName, UserName]) //Change ImageFileName to the executable name
| groupBy([ComputerName, UserName], function=collect([DomainName, CommandLine, ImageFileName], limit=1000))
```


## List Created and Deleted Files - Windows
```text
aid=?aid
#event_simpleName="*FileWritten"
OR #event_simpleName=*ExecutableWritten
OR #event_simpleName=*ScriptWritten
OR #event_simpleName=FileCreateInfo
OR #event_simpleName=RansowareCreateFile
OR #event_simpleName=QuarantinedFile
OR #event_simpleName=FileDeleted*
//AND #event_simpleName!=EseFileWritten
//| TargetFileName!=*\GroupPolicy\*
//| TargetFileName!=*\Netskope\*
| table([@timestamp, #event_simpleName, ContextBaseFileName, FileName, TargetFileName], limit=10000)
```


## PHP Files on a Host
```text
aid=?aid
#event_simpleName="NewScriptWritten"
| FileName = "*.php"
| TargetFileName = *
OR #event_simpleName=*ExecutableWritten
OR #event_simpleName=*ScriptWritten
OR #event_simpleName=FileCreateInfo
OR #event_simpleName=RansowareCreateFile
OR #event_simpleName=QuarantinedFile
OR #event_simpleName=FileDeleted*
//AND #event_simpleName!=EseFileWritten
//| TargetFileName!=*\GroupPolicy\*
//| TargetFileName!=*\Netskope\*
| table([@timestamp, #event_simpleName, ContextBaseFileName, FileName, TargetFileName], limit=10000)
```


## Browser Extensions
```text
#event_simpleName=InstalledBrowserExtension BrowserExtensionId!="no-extension-available"
| groupBy([event_platform, BrowserName, BrowserExtensionId, BrowserExtensionName], function=([count(aid, distinct=true, as=TotalEndpoints)]))
| test(TotalEndpoints<50)
| format("[See Extension](https://chromewebstore.google.com/detail/%s)", field=[BrowserExtensionId], as="Chrome Store Link")
| sort(order=desc, TotalEndpoints, limit=1000)
| case{
BrowserName="3" | BrowserName:="Chrome";
BrowserName="4" | BrowserName:="Edge";
*;
}
```

## Number of Extensions on Each Endpoint
```text
#event_simpleName=InstalledBrowserExtension BrowserExtensionId!="no-extension-available"
| groupBy([BrowserExtensionName], function=([count(aid, distinct=true, as=TotalEndpoints)]))
| sort(TotalEndpoints, order=desc)
```


## VPN Extensions
```text
#event_simpleName=InstalledBrowserExtension BrowserExtensionId!="no-extension-available"
| BrowserExtensionName=/vpn/i
| Extension:=format(format="%s (%s)", field=[BrowserExtensionId, BrowserExtensionName])
| groupBy([event_platform, aid, ComputerName, UserName, BrowserProfileId, BrowserName], function=([collect([Extension])]))
| drop([_count])
| case{
BrowserName="3" | BrowserName:="Chrome";
BrowserName="4" | BrowserName:="Edge";
*;
}
```


## Third-Party Extensions
```text
#event_simpleName=InstalledBrowserExtension BrowserExtensionId!="no-extension-available"
| in(field="BrowserExtensionInstallMethod", values=[4,5])
| Extension:=format(format="%s (%s)", field=[BrowserExtensionId, BrowserExtensionName])
| groupBy([event_platform, aid, ComputerName, UserName, BrowserProfileId, BrowserName, BrowserExtensionInstallMethod], function=([collect([Extension])]))
| drop([_count])
| case{
BrowserName="3" | BrowserName:="Chrome";
BrowserName="4" | BrowserName:="Edge";
*;
}
| case{
BrowserExtensionInstallMethod="4" | BrowserExtensionInstallMethod:="Sideload";
BrowserExtensionInstallMethod="5" | BrowserExtensionInstallMethod:="Third-Party Store";
*;
}
```

## PowerShell Calls for DNS
```text
#event_simpleName=DnsRequest event_platform=Win ContextBaseFileName=powershell.exe
| DomainName!=/(.?test.com$)/
| case {
    test(@timestamp < (now() - duration(1d))) | HistoricalState:="1";
    test(@timestamp > (now() - duration(1d))) | CurrentState:="1";
}
| default(value="0", field=[HistoricalState, CurrentState])
| groupBy([DomainName], function=[max("HistoricalState",as=HistoricalState), max(CurrentState, as=CurrentState), max(ContextTimeStamp, as=LastSeen), count(aid, as=ResolutionCount), count(aid, distinct=true, as=EndpointCount), collect([FirstIP4Record])], limit=max)
| HistoricalState=0 AND CurrentState=1
```


## Files named "senha,passw,pwd"
```text
#repo=base_sensor #event_simpleName=* FileName=*
| FullFile:=concat([TargetFileName, ImageFileName])
| FileName=/(senha|passw|pwd).+(xlsx?|txt|docx?)$/i
| table([aid, ComputerName, #event_simpleName, FullFile])
```


## Getting linux inventory
```text
#event_simpleName=OsVersionInfo event_platform=Lin
| OSVersionFileData=*
| replace("([0-9A-Fa-f]{2})", with="%$1", field=OSVersionFileData, as=OSVersionFileData)
| OSVersionFileData:=urlDecode("OSVersionFileData")
| OSVersionFileData=/NAME\=\"(?<DistroName>.+)\"\sVERSION\=\"(?<DistroVersion>.+)\"\sID/
| Distro:=format(format="%s %s", field=[DistroName, DistroVersion])
| groupBy([Distro], function=([count(aid, distinct=true, as=TotalSystems)]))
| sort(TotalSystems, order=desc)
```


## Package "xz" validation - useful for hunting a specific cve in the environment
```text
#event_simpleName=ProcessRollup2 FileName=/^xz(\-\w+)?$/
| in(field="event_platform", values=[Lin])
| groupBy([aid, ComputerName, FileName, FilePath], function=([selectLast([ProcessStartTime])]))
| LastExecution:=ProcessStartTime*1000 | LastExecution:=formatTime(format="%F %T.%L", field="LastExecution")
| drop([ProcessStartTime])
```


## Brute force RDP
```text
aid=?aid AND #event_simpleName="*Logon*" | table([#event_simpleName, UserName, RemoteIP, @timestamp, ComputerName], limit=1000)
```


## Last Logons
```text
#event_simpleName=UserLogon
aid=?aid
| #event_simpleName=UserLogon
| $falcon/helper:enrich(field=LogonType)
| table([@timestamp, ComputerName, ComputerName, UserName, LogonType], limit=10000)
```


## Brute Force
```text
#event_simpleName" = UserLogonFailed2 |
groupBy([UserName,ComputerName])
| test(_count > 100) // Replace X with your desired threshold number
```


## Logons
```text
#event_simpleName=UserLogon
| UserUUID:=UserSid | UserUUID:=UID
| groupBy([aid], function=([selectFromMax(field="@timestamp", include=[ComputerName, UserUUID, UserName, LogonType, @timestamp])]))
| $falcon/helper:enrich(field=LogonType)
| aid=~match(file="aid_master_main.csv", column=[aid])
```


## Calls from a process to an ip
```text
#event_simpleName=Network* AND RemoteIP=*
| aid=0f615b2254e04133ba0bd0e0d097cee9
| table(fields = [ComputerName, #event_simpleName, ContextBaseFileName, RemoteIP, RemotePort, LocalIP, LocalPort, ConnectionDirection, @timestamp])
| ContextBaseFileName = java
```


## AD Events
```text
#event_simpleName=ActiveDirectoryAuditUserModified
```





