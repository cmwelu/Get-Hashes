<#
.SYNOPSIS
A Powershell script to acquire and count file hashes on systems.

.DESCRIPTION
This script utilizes Get-FileHash to obtain hashes from files with pre-defined (executable) extensions recursively, starting from a user-defined directory. 
Hashes can be obtained from multiple computers, and frequency analysis can be performed for a DFIR perspective. 

.PARAMETER ComputerName
An array of fully qualified computer names to collect data from. If none is specified, the local machine will be collected from.

.PARAMETER StartingPath
The path to begin a recursive search for files. Default: C:\

.PARAMETER Algorithm
The hashing algorithm to be used. Default: SHA256

.PARAMETER CountAll
A switch to count the number of occurrences of all hashes. 

.PARAMETER CountUnique
A switch to return only hashes that occur once.

.PARAMETER SleepSecs
Seconds to sleep while jobs are running. Default: 10

.PARAMETER Credential
Alternate credentials to authenticate to remote systems

.EXAMPLE
./Get-Hashes.ps1 -StartingPath "C:\Windows\System32"
Gets hashes from executable files in C:\Windows\System32 on the local computer


.EXAMPLE
Get-Content computerList.txt | ./Get-Hashes.ps1 -StartingPath "C:\Program Files" -CountUnique
Get hashes that appear only once in C:\Program Files across all computers in computerList.txt

.LINK
https://github.com/cmwelu/Get-Hashes

#>
[CmdletBinding()]

Param(

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]

        [string[]] $ComputerName,

    [string]$StartingPath = "C:\",
    [string]$Algorithm="SHA256",
    [switch]$CountAll = $false,
    [switch]$CountUnique = $false,
    [int]$SleepSecs = 10,
    [System.Management.Automation.PSCredential]$Credential = (Get-Credential)

)
process
{
    
    function Get-Hashes($StartingPath, $Extensions, $Algorithm)
    {
       
        $Hostname=hostname
        $hashes =@()

        #Find files recursively that end in a specified extension
        $files = Get-ChildItem $StartingPath -Recurse | where-object {$_.Extension -In $Extensions} 
        $FileCount = $files.count
        Write-Host "Found $FileCount files on $Hostname"

        #Hash each file
        $i = 0
        Foreach($file in $files)
        {
            $i++
            
            #Write-Progress -Activity "Calculating Hashes on $Hostname" -Status "Hashing file $i of $FileCount" -PercentComplete ($i/$FileCount*100)
            $hash = (Get-FileHash $file.FullName -Algorithm $Algorithm)
            $hash | Add-Member -NotePropertyName ComputerName -NotePropertyValue $Hostname
            $hashes += $hash
        }
        $hashes
    }

    #---------------------MAIN--------------------------

    #SmallList
    #$Extensions = @(".dll", ".exe", ".ps1", ".bat", ".msi")
    
    #LargeList
    #Source: http://www.thepreparednesspodcast.com/quick-list-on-executable-file-extensions-updated/
    $Extensions = @(".bat", ".bin", ".cmd", ".com", ".cpl", ".exe", ".gadget", ".inf", ".ins", ".inx", ".isu", ".job", ".jse", ".lnk", ".msc", ".msi", ".msp", ".mst", ".paf", ".pif", ".ps1", ".reg", ".rgs", ".sct", ".shb", ".shs", ".u3p", ".vb", ".vbe", ".vbs", ".vbscript", ".ws", ".wsf")
    
    if(!$ComputerName)
    {
        #Collect hashes from the local system
        $HashesOut = Get-Hashes $StartingPath $Extensions $Algorithm
    }
    else
    {
        #Start jobs to collect hashes from remote systems
        $Jobs = Invoke-Command -ComputerName $ComputerName -ScriptBlock ${function:Get-Hashes} -ArgumentList $StartingPath, $Extensions, $Algorithm -AsJob 
    }
}
end
{
    #Collect Jobs
    if($ComputerName)
    {
        While(Get-Job -State "Running")
        {
            $running = Get-Job -State "Running"
            Write-Host "Job running on:" $running.Location
            Write-Host "  Waiting..."
            Start-Sleep $SleepSecs
        }

        $HashesOut = Get-Job | Receive-Job
    }

    #Output options
    if(!$CountAll -and !$CountUnique)
    {
        $HashesOut | Select-Object PSComputerName, Hash, Path
    }
    elseif($CountAll)
    {
        $HashesOut | Select-Object PSComputerName, Hash, Path | Group-Object -Property Hash | Sort-Object -Descending Count
    }
    elseif($CountUnique)
    {
        $HashesOut | Select-Object PSComputerName, Hash, Path | Group-Object -Property Hash | Where-Object Count -eq 1
    }
}