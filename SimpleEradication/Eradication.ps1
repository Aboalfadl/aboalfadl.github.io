#This tool is coded by dark@aboalfadl.com to kill some processes and clean system from specific malicious files based on MD5 hashes


$error.Clear()
$stopwatch = [System.Diagnostics.Stopwatch]::new()
$Stopwatch.Start()
$IP = (Get-NetIPAddress | Where-Object {$_.AddressState -eq "Preferred" -and $_.ValidLifetime -lt "24:00:00"}).IPAddress
$Currunt = Get-Location
$LogPath = "$($Current)$($IP)_$($env:COMPUTERNAME).txt"
Start-Transcript -Path $LogPath

# Kill Malicious Processes if you know the name just set the names here

$ProcessName1 = "INSERT A MALICIOUS PROCESSNAME TO KILL"
$ProcessName2 = "INSERT A MALICIOUS PROCESSNAME TO KILL"
$ProcessName3 = "INSERT A MALICIOUS PROCESSNAME TO KILL"
$ProcessName4 = "INSERT A MALICIOUS PROCESSNAME TO KILL"
$ProcessName5 = "INSERT A MALICIOUS PROCESSNAME TO KILL"

$ErrorActionPreference = "SilentlyContinue"

# Insert the malicious hashes you need to clean here as the following example:

$MalHashes = @("21469e3861359bf3bc0a9796d0be0826", "c43abc93efa3815d6fe997bb3c56f550", "228a04d9832da0ed3e8ba740737f3b7c")

$MainPaths = @("C:\" , "C:\Windows")
$UsersPath = "C:\Users\"
$InPath = @("C:\Program Files" , "C:\Program Files (x86)" , "C:\ProgramData" , "C:\Windows\System32" , "C:\ProgramData\Microsoft" , "C:\Windows\Temp")


Write-Output "---------------------------------------------------------"
Write-Output "---------------------------------------------------------"
Write-Output "-----Simple Eradication Script by Dark@aboalfadl.com-----"
Write-Output "---------------------------------------------------------"
Write-Output "---------------------------------------------------------"
Write-Output "`n"
Write-Output "Cleaner started at $(Get-Date -format "O") on machine: $($env:COMPUTERNAME)" 
Write-Output "`n"
Write-Output "--------------------------------"
Write-Output "Gathering Network Information"
Write-Output "--------------------------------"
Get-NetIPConfiguration
Write-Output "`n"
Write-Output "--------------------------------"
Write-Output "Gathering Enabled Users"
Write-Output "--------------------------------"

$enabledusers = Get-LocalUser | Where-Object -Property Enabled -eq True
$enabledusers.name
$hashes = @()
Write-Output "--------------------------------"
Write-Output "Calculcating System Files Hashes"
Write-Output "--------------------------------"
# Get Users Files
$Users = $enabledusers.name
$Users | ForEach-Object{
    $User = $_
    $UserPath = "$($UsersPath)$($User)"
    $UserPath
    $Userhashes = dir $UserPath -Recurse -Depth 10 -Force | Where-Object {!$_.psiscontainer } | Get-FileHash -Algorithm MD5 -ea 0
    $hashlength = $Userhashes.Length
    Write-Output "Hashes Count : $hashlength"
    $hashes += $Userhashes
}
# Get 2 level of Important Path

$InPath | ForEach-Object{
    $Path = $_
    $Path
    $Dirhasesh = dir $Path -Recurse -Depth 2 -Force | Where-Object {!$_.psiscontainer } | Get-FileHash -Algorithm MD5 -ea 0
    $hashlength = $Dirhasesh.Length
    Write-Output "Hashes Count : $hashlength"
    $hashes += $Dirhasesh
}

$MainPaths | ForEach-Object{
    $Path = $_
    $Path
    $Dirhasesh = dir $Path -Recurse -Depth 1 -Force | Where-Object {!$_.psiscontainer } | Get-FileHash -Algorithm MD5 -ea 0
    $hashlength = $Dirhasesh.Length
    Write-Output "Hashes Count : $hashlength"
    $hashes += $Dirhasesh
}


$AllHashesCount = $hashes.Length
Write-Output "Hashes Count = $AllHashesCount"
Write-Output "Comparing hashes, please wait..."
Write-Output "`n"
Write-Output "-----------------------------"
Write-Output "Hashes Count = $AllHashesCount"
Write-Output "-----------------------------"
Write-Output "`n"
Write-Output "Cleaning Process Is Started (Malicious Files and Processes related will be cleaned) ..."
Write-Output "---------------------------------------------------------------------------------------"
Write-Output "`n"
$count = 0
$hashcount = 1
Write-Output "---------------------------------------"
Write-Output "$AllHashesCount hashes will be examined"
Write-Output "---------------------------------------"

$hashes | ForEach-Object{
  $hash = $_
  Write-Progress -Activity "Scanning in Progress" -Status "$(($hashcount / $AllHashesCount)*100)% Complete:" -PercentComplete (($hashcount / $AllHashesCount)*100);
  #Write-Output $hash
  $MalHashes | ForEach-Object{
    $malicioushash = $_
    #Write-Output "handling now .. " $malicioushash
    if ($malicioushash -in $hash.Hash)
    {
        
        if ( $MaliciousProcess = Get-Process $ProcessName1 , $ProcessName2, $ProcessName3 , $ProcessName4 , $ProcessName5 )
        {
            Write-Output "--------------------------"
            Write-Output "Searching for Malicious Processes...."
            Write-Output "--------------------------"
            $MaliciousProcess
            $MaliciousProcess.kill()
            Write-Output "--------------------------"
            Write-Output "Malicious Processes have been killed...."
            Write-Output "--------------------------"


        else {Write-Warning "Malicious Processes not found"}

        }
        Write-Output "Malicious hash Found....$malicioushash"
        try
        {
            Remove-Item -Path $hash.Path -Force
            Write-Output "$($hash.Path) has been cleaned successfully"
            Write-Output "`n"
            $count = $count + 1
        }
        catch 
        {
            Write-Output "$($hash.Path) Error while cleaning "
            Write-Output "`n"
        }       
    }

  }
  $hashcount += 1
}

if ($count -eq 0)
{
    Write-Output  "Your System is clean nothing to remove."
    $ScriptSeconds = $Stopwatch.Elapsed.TotalSeconds
    Write-Output  "This Cleaner took $ScriptSeconds Seconds to finish "
    Stop-Transcript
}
else
{
    Write-Output "-----------------------------------------------------"
    Write-Output  "$count Malicious File has been Found and successfully deleted from the system"
    $ScriptSeconds = $Stopwatch.Elapsed.TotalSeconds
    Write-Output  "This Cleaner took $ScriptSeconds Seconds to finish "
    Stop-Transcript
}

