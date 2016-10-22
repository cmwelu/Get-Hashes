#Get-Hashes

##Overview
This PowerShell script acquires hashes from remote systems recursively from a user-defined starting location across a number of machines. Frequency analysis is performed on the collected hashes, and reported to the user. Unique hashes could be taken from this tool and uploaded to VirusTotal.

Note: This script was created during Dakota State University's CSC-842 Rapid Tool Development course.

##Usage
```PowerShell
 .\Get-Hashes.ps1 [[-ComputerName] <String[]>] [[-StartingPath] <String>] [[-Algorithm] <String>] [-CountAll]
 [-CountUnique] [[-SleepSecs] <Int32>] [[-Credential] <PSCredential>] [<CommonParameters>]
```

For detailed help and examples, run 
````PowerShell
Get-Help .\Get-Hashes.ps1
````

##Resources
* [Video Demo](https://youtu.be/RqlrC3-z9jk)
