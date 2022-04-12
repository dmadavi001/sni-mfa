<#-----------------------------------------------------------------------------
 Testing Center of Excellence - Alpha Test Scripts

 Powershell Testing with Pester


-----------------------------------------------------------------------------


## ServiceTests.Tests.ps1
#>

if(Test-Path C:\Pester){
		
}

else{
	New-Item -Path 'C:\Pester' -ItemType Directory
}

$testdate = (get-date -f MMddyyyy_HHmmss)

New-Item -ItemType Directory -Path "C:\Pester\$testdate"

Set-Location -Path C:\Pester\$testdate	


Start-Transcript -Path .\AlphaTestOutput_$(get-date -f MMddyyyy_HHmmss).log -Force

Describe 'Status of PwC security agents on localhost' {

        it 'Thycotic should be running' {
		$status = (Get-Service -Name 'ArelliaAgent').Status
         	$status | should -Be 'Running'
    	}
    
    
        it 'Windows Defender should be running' {
		$status = (Get-Service -Name 'WinDefend').Status
        	$status | should -Be 'Running'
    	}
    
    
        it 'GlobalProtect should be running' {
		$status = (Get-Service -Name 'PanGPS').Status
        	$status | should -Be 'Running'
   	}
    
    
        it 'Qualys Cloud Agent should be running' {
		$status = (Get-Service -Name 'QualysAgent').Status
        	$status | should -Be 'Running'
    	}
    
    
        it 'Digital Guardian should be running' {
		$status = (Get-Service -Name 'DGService').Status
        	$status | should -Be 'Running'
    	}

    
        it 'Splunk should be running' {
		$status = (Get-Service -Name 'SplunkForwarder').Status
        	$status | should -Be 'Running'
    	}

   
        it 'uberAgent should be running' {
		$status = (Get-Service -Name 'uberAgentSvc').Status
        	$status | should -Be 'Running'
    	}

		it 'Flexera Inventory Manager managed should be running' {
        $status = (Get-Service -Name 'ndinit').Status
        $status | should -Be 'Running'
    	}

		it 'Flexera Inventory Manager security should be running' {
			$status = (Get-Service -Name 'mgssecsvc').Status
			$status | should -Be 'Running'
		}

		it 'Program should have exited successfully' {

			for ($i=1; $i -le 3; $i++){

				$trimmedLog = (Get-Content -Path C:\Windows\Temp\ManageSoft\installation.log | Select -Last 1).substring(36)
				Start-Sleep -Seconds 3
			
			}

        	$trimmedLog | should -Be 'Program exited successfully'
    	}

}
    
Describe 'Available Software Checks' {

    context 'Standard installation location installs' {

    	BeforeAll {
        	$installsList = [collections.generic.list[psobject]]::new()

        	$installs64 =  Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' | Get-ItemProperty |
            Select-Object DisplayName, DisplayVersion

        	$installs32 =  Get-ChildItem -Path 'HKLM:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\' | Get-ItemProperty |
            Select-Object DisplayName, DisplayVersion

        	$installs64 | ForEach-Object {$installsList.Add($_)}
        	$installs32 | ForEach-Object {$installsList.Add($_)}
     	}

        it 'should have GlobalProtect installed' {
            ($installsList | Where-Object -Property DisplayName -eq 'GlobalProtect').DisplayVersion | Should -BeLike "5*"
        }
        it 'should have Google Chrome version 75 or higher installed' {
             ($installsList | Where-Object -Property DisplayName -eq 'Google Chrome').DisplayVersion | Should -BeGreaterOrEqual "75*"
        }
        it 'should have Thycotic version 10.5 or higher' {
             ($installsList | Where-Object -Property DisplayName -eq 'Thycotic Agent').DisplayVersion | Should -BeGreaterOrEqual "10.5*"
        }
        it 'should have Cylance PROTECT version 2.0.1540 or higher installed' {
             ($installsList | Where-Object -Property DisplayName -eq 'Cylance PROTECT').DisplayVersion | Should -BeGreaterOrEqual "2.0.1540*"
        }
        it 'should have Workspace ONE Intelligent Hub 18.0 or higher installed' {
             ($installsList | Where-Object -Property DisplayName -eq 'Workspace ONE Intelligent Hub Installer').DisplayVersion | Should -BeGreaterOrEqual "18*"
        }
        it 'should have raPRO installed' {
             ($installsList | Where-Object -Property DisplayName -eq 'raPro').DisplayVersion | Should -BeLike "2*"
        }
        it 'should have Splunk Universal Forwarder 7.0 or higher installed' {
             ($installsList | Where-Object -Property DisplayName -eq 'UniversalForwarder').DisplayVersion | Should -BeGreaterOrEqual "7*"
        }
        it 'should have Digital Guardian 7.5 or higher installed' {
             ($installsList | Where-Object -Property DisplayName -eq 'Digital Guardian Agent').DisplayVersion | Should -BeGreaterOrEqual "7.5*"
        }
		it 'should have FlexNet Inventory Agent 16.0.1 or higher installed' {
             ($installsList | Where-Object -Property DisplayName -eq 'FlexNet Inventory Agent').DisplayVersion | Should -BeGreaterOrEqual "16.0.1*"
        }

    }

}

Describe "Check Services that are 'Running' and 'Stopped'" {
    
        It "Services- Running" {
            Get-Service | Where-Object {$_.Status -eq "Running"} | Out-File -FilePath .\RunningServices.log
        }

	It "Services- Stopped" {
            Get-Service | Where-Object {$_.Status -eq "Stopped"} | Out-File -FilePath .\StoppedServices.log
        }
}




Describe "Check workstation" {
    Context "Check service status"{
        It "VSS service status - stopped" {
            (Get-Service -Name VSS).Status| Should -Be Stopped
        }
 
        It "Firewall service status - running" {
            (Get-Service -Name MpsSvc).Status| Should -Be Running
        }
    }
     
    Context "Check free disk space"{
        It "C drive free space greater than 20 GB" {
            (Get-WmiObject win32_logicaldisk -Filter "Drivetype=3" | Where-Object {$_.DeviceID -eq "C:"}).FreeSpace/1GB | Should -BeGreaterThan 20
        }
 
    }
     
    Context "Check RAM usage"{
        It "Free RAM greater than 4GB" {
            (Get-Ciminstance Win32_OperatingSystem | Select-Object FreePhysicalMemory).FreePhysicalMemory/1mb | Should -BeGreaterThan 4
        }
 
    }
    
}




Describe 'Cylance Policy Check' {

	BeforeAll {

    		$CylancePolicy = Get-Content C:\ProgramData\Cylance\Status\Status.json | ConvertFrom-Json 
    		$CylancePolicyStatus = $CylancePolicy | Select -ExpandProperty Policy | Select Type | ft -HideTableHeaders | Out-String
    		$CylancePolicyName = $CylancePolicy | Select -ExpandProperty Policy | Select name | ft -HideTableHeaders | Out-String
 	}
    
        it 'Cylance policy should be Online' {
        	$CylancePolicyStatus.Trim() | should -Be 'Online'
    	}
    

        it 'Cylance policy name should be 3' {
        	$CylancePolicyName.Trim() | should -BeLike '3*'
    	}



}

Describe 'Export RaPro Certificates' {

        

	it 'RaProCertificates.CSV should exist' {
	$RaProCertificate =  Get-ChildItem -Path Cert:\ -Recurse |Where-Object {-not $_.PSIContainer} | Select PSPath,Subject,FriendlyName,Issuer,NotBefore,NotAfter | Export-CSV RaProCertificates.CSV  -NoTypeInformation
		"RaProCertificates.CSV" | Should -Exist
	}
	

	
	it 'Should be true' {

	(Get-ChildItem Cert:\CurrentUser\My\ -Recurse | Where-Object {$_.Issuer -like "CN=PwC AURA Issuing - 1, DC=pwc, DC=com"}).HasPrivateKey  | Should -Be 'True'

	}
	
}


Describe 'Export Workstation Certificates' {

        
	it 'WorkstationCertificates.CSV should exist' {
	  $Workstationcertificate =  Get-ChildItem Cert:\LocalMachine\My\ -Recurse | Where-Object{ $_.psiscontainer -eq $false} | fl -property * | Export-CSV WorkstationCertificates.CSV -NoTypeInformation

		"WorkstationCertificates.CSV" | Should -Exist
	}
	
}

Describe 'Printing' {

	

	it 'should print to all attached print devices' {
	 	$MyPrinters = Get-Printer | Select Name
		foreach ($printer in $MyPrinters) {
			Write-Host "THIS IS A TEST PRINT SENT TO PRINTER: "$printer.name
		}
		"$MyPrinters" | Should -Exist
	}
}


Describe 'Check the client renews the IP address via DHCP' {

	


	
	it 'should have IP Address after release/renew' {
	$IPAddress1 = Ipconfig /all | Out-File -FilePath .\Ipconfig.log
	$IPAddress2 = Get-NetIPAddress -AddressState Preferred -AddressFamily IPv4 | Select-Object IPAddress,InterfaceAlias
            ($IPAddress2.IPAddress) | Should -Not -BeNullOrEmpty
	
	}
}





Describe 'Test Internet Access' {

	

	 it 'TcpTestSucceeded should be True' {
	  $TestInternet = Test-NetConnection www.bbc.com -Port 80

          ($TestInternet | Where-Object -Property ComputerName -eq 'www.bbc.com').TcpTestSucceeded | Should -Be "True"
	
	}
}


	
Start-Sleep -Second 10



Describe 'Check the  DNS Subzone validation' {


	

	 it 'should validate the DNS subzone configuration' {
	$DNScheck = nslookup -type=all pwcglb.com | Out-File -FilePath .\DNS.log

	 '.\DNS.log' | Should -FileContentMatch 'primary name server'
	
            
	
	}
}


Describe 'Check the  DNS Resolution & AD Site' {


	 it 'should validate the DNS Resolution & AD Site' {
		$DNScheck = Resolve-DnsName pwcglb.com -Type A | Measure-Object -Line
		$DNScheck1 = NLTest /dsgetdc:pwcglb.com
		$DNScheck2 = NLTest /dsgetdc:pwcglb.com | Out-File -FilePath .\DNSResolution.log


	
		 ($DNScheck).Lines | Should -BeGreaterOrEqual "21"
	 	($DNScheck1) | Should -Not -BeNullOrEmpty
            
	
	}
}

Describe 'DNS Platform Test' {

	$output = Get-DnsClient | Select -property InterfaceAlias,InterfaceIndex,ConnectionSpecificSuffix | Out-File -FilePath .\DNSPlatformTest.log 
	
}

Describe 'Check Drive Mappings' {

	$output = net use | Out-File -FilePath .\DriveMappings.log 
	$output1 =  net share >> .\DriveMappings.log
	
}


Describe 'System Performance' {


	$CPUUsage = Write "CPU Usage %" (Get-WmiObject win32_processor).LoadPercentage | Out-File -filepath .\Systemperformance.log

	$DetailedProcessorUsage = Get-Counter -Counter "\Processor(*)\% Processor Time" >> .\Systemperformance.log 

	$SystemInfo = systeminfo >> .\Systemperformance.log 
}





Stop-Transcript