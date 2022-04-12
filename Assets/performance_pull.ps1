#
#
#####################################
#    TCOE Performance Pull Script   #
#####################################
#
######################
#    Instructions    #
######################
#
# 1. Within PowerShell, navigate to the directory where the TCOE_Performance_Pull.ps1 script is located
# 2. Execute the script in PowerShell by entering the following command: .\TCOE_Performance_Pull.ps1
# 3. Within the same directory, a file called TCOE_Report.csv will be created
# 4. Open the file after the script has completed and load into your preferred data processing tool of choice. 
#    NOTE: The script will take approximately 7-10 minutes to complete.
#
# Author - Chad Eckles (chad.eckles@pwc.com)
# Date- 02 October 2019
#
$localhost = $env:computername
$Counters = @(
       "\PhysicalDisk(*)\% Idle Time",
       "\PhysicalDisk(_total)\Avg. Disk sec/Read",
       "\PhysicalDisk(_total)\Avg. Disk sec/Write",
       "\Memory\Pages/sec",
       "\Memory\Available MBytes",
       "\Processor(_total)\% Processor Time",
       "\Network Interface(*)\Bytes Total/sec",
       "\Network Interface(*)\Output Queue Length",
       "\LogicalDisk(C:)\% Free Space",
       "\LogicalDisk(*)\Avg. Disk Queue Length"
)
Get-Counter -Counter $Counters -MaxSamples 500 | ForEach {
    $_.CounterSamples | ForEach {
        [pscustomobject]@{
            TimeStamp = Get-Date -Format "MM_dd_yyyy-HH:mm:ss"
            Path = $_.Path
            Value = $_.CookedValue
        }
    }
} | Export-Csv -Path TCOE_Report.csv -NoTypeInformation