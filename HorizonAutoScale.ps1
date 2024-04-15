function Get-HorizonHeader(){
    param($accessToken)
    return @{
        'Authorization' = 'Bearer ' + $($accessToken.access_token)
        'Content-Type' = "application/json"
    }
}

function Open-HorizonConnection(){
    param(
        [string] $username,
        [string] $password,
        [string] $domain,
        [string] $url
    )

    $Credentials = New-Object psobject -Property @{
        username = $username
        password = $password
        domain = $domain
    }
    return Invoke-Restmethod -Method Post -uri "$url/rest/login" -ContentType "application/json" -Body ($Credentials | ConvertTo-Json)
}

function Close-HorizonConnection(){
    param(
        $accessToken,
        $url
    )
    return Invoke-RestMethod -Method post -uri "$url/rest/logout" -ContentType "application/json" -Body ($accessToken | ConvertTo-Json)
}

function Write-log {
    [CmdletBinding()]
    Param(
          [parameter(Mandatory=$true)]
          [String]$Path,

          [parameter(Mandatory=$true)]
          [String]$Message,

          [parameter(Mandatory=$true)]
          [String]$Component,

          [Parameter(Mandatory=$true)]
          [ValidateSet("Info", "Warning", "Error")]
          [String]$Type
    )

    switch ($Type) {
        "Info" { [int]$Type = 1 }
        "Warning" { [int]$Type = 2 }
        "Error" { [int]$Type = 3 }
    }

    # Create a log entry
    $Content = "<![LOG[$Message]LOG]!>" +`
        "<time=`"$(Get-Date -Format "HH:mm:ss.ffffff")`" " +`
        "date=`"$(Get-Date -Format "M-d-yyyy")`" " +`
        "component=`"$Component`" " +`
        "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
        "type=`"$Type`" " +`
        "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " +`
        "file=`"`">"

    # Write the line to the log file
    Add-Content -Path $Path -Value $Content
}

#region Initialize Logging
if ($psISE)
{
    $LogFilePath = Join-Path $(Split-Path -Path $psISE.CurrentFile.FullPath) "logs\$(Get-Date -Format yyyy-MM-dd)_$(Split-Path -Leaf $psISE.CurrentFile.FullPath).log"    
}
else
{
    $LogFilePath = Join-Path $PSScriptRoot "logs\$(Get-Date -Format yyyy-MM-dd)_$($MyInvocation.MyCommand.Name).log"
}
Write-log -Path $LogFilePath -Message "START - Logging in..." -Component "Initialize" -Type Info
#endregion

#region Security Module
try {
    Import-Module CredentialManager
    $Credentials = Get-StoredCredential -Target HorizonAutoScaleAPI # Store your credentials one time by execute New-StoredCredentials in the future running user-context
    $username = $Credentials.UserName
    $password = $Credentials.Password
    Write-log -Path $LogFilePath -Message "Credentials for $username loaded" -Component "Security Module" -Type Info
} catch {
    Write-Error ($_ | Out-String)
    Write-Log -Path $LogFilePath -Message ($_ | Out-String) -Component $MyInvocation.MyCommand.Name -Type Error
}
#endregion

#region Define Horizon Environment
$url = "" #-> Add your Horizon URL
$domain = "" #-> Add your Windows Domain
# Replaced with Secure CredentialManager
#$username = "" #-> If not using Credential Manager
#$password = read-host -prompt "Password" -AsSecureString #-> If not using Credential Manager
#endregion

#region Settings
$FarmName2AutoScale = "" #-> Add your Farm-Name here
$AvgNumberofUserperRDSServerThreshold = 9 #-> User threshold where Auto-Scale shall init a new RDS-Host
$LoadIndexThreshold = 80 #-> Load threshold where Auto-Scale shall init a new RDS-Host
$MinNumberofRDSServers = 1 #-> Minimum number of RDS-Hosts in the defined farm
$MaxNumberofRDSServers = 6 #-> Maximum number of RDS-Hosts in the defined farm
#endregion

#region Calculation
try {
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $accessToken = Open-HorizonConnection -username $username -password $UnsecurePassword -domain $domain -url $url
    Write-log -Path $LogFilePath -Message "Connected to $url" -Component "Calculation" -Type Info

    $HorizonFarms = Invoke-RestMethod -Method Get -uri "$url/rest/monitor/farms" -ContentType "application/json" -Headers (Get-HorizonHeader -accessToken $accessToken)
    $ChoosenHorizonFarm = $HorizonFarms | Where-Object {$_.name -eq $FarmName2AutoScale}
    $RDSServers = Invoke-RestMethod -Method Get -uri "$url/rest/monitor/rds-servers" -ContentType "application/json" -Headers (Get-HorizonHeader -accessToken $accessToken) 
    $RDSServersInFarm = $RDSServers | Where-Object {$_.farm_id -eq $ChoosenHorizonFarm.id} | Sort-Object name -Descending
    $SessionCount = ($RDSServersInFarm | Measure-Object -Property session_count -Sum).Sum
    Write-log -Path $LogFilePath -Message "We have $SessionCount total sessions on $($ChoosenHorizonFarm.rds_server_count) RDS-Servers in Farm $FarmName2AutoScale" -Component "Calculation" -Type Info

    #Calculate users
    $OptimizedRDSServerCount = [math]::ceiling($SessionCount/$AvgNumberofUserperRDSServerThreshold)
    
    #Calculate load
    If($OptimizedRDSServerCount -eq $ChoosenHorizonFarm.rds_server_count){
        $LoadIndexOK = $false # assume farm is overloaded
        for($i=0; $i -lt $ChoosenHorizonFarm.rds_server_count; $i++){
            Write-log -Path $LogFilePath -Message "Server $($RDSServersInFarm[$i].name) ($($RDSServersInFarm[$i].details.state)) has $($RDSServersInFarm[$i].session_count) session(s) and an overall load of $($RDSServersInFarm[$i].load_index)" -Component "Calculation" -Type Info
            if($RDSServersInFarm[$i].load_index -lt $LoadIndexThreshold){
                $LoadIndexOK = $true # correcting assumption
            }
        }
        if($LoadIndexOK -eq $false){
            $OptimizedRDSServerCount++ # correcting suggestion by adding one additional server
            Write-log -Path $LogFilePath -Message "Adding one additional RDS-Server due to high load situation" -Component "Calculation" -Type Info
        }
    }
    
    #Min/Max correction
    If($OptimizedRDSServerCount -gt $MaxNumberofRDSServers){$OptimizedRDSServerCount = $MaxNumberofRDSServers}
    If($OptimizedRDSServerCount -lt $MinNumberofRDSServers){$OptimizedRDSServerCount = $MinNumberofRDSServers}
    Write-log -Path $LogFilePath -Message "According defined $AvgNumberofUserperRDSServerThreshold Users per RDS and overall Load-Index the calculated optimum is $OptimizedRDSServerCount RDS-Server(s); Min:$MinNumberofRDSServers Max:$MaxNumberofRDSServers" -Component "Calculation" -Type Info

} catch {
    Write-Error ($_ | Out-String)
    Write-Log -Path $LogFilePath -Message ($_ | Out-String) -Component $MyInvocation.MyCommand.Name -Type Error
}
#endregion

#region Farm Update
#Increase/Decrease max_number_of_rds_servers for given Farm
If($OptimizedRDSServerCount -ne $ChoosenHorizonFarm.rds_server_count){
    try {
        #Receive CustomObject
        $ChoosenHorizonFarmSettings = Invoke-RestMethod -Method Get -uri "$url/rest/inventory/v5/farms/$($ChoosenHorizonFarm.id)" -ContentType "application/json" -Headers (Get-HorizonHeader -accessToken $accessToken)
    
        #Change Farm Size to OptimizedRDSServerCount
        Write-log -Path $LogFilePath -Message "Attempt to change max_number_of_rds_servers from $($ChoosenHorizonFarmSettings.automated_farm_settings.pattern_naming_settings.max_number_of_rds_servers) to $OptimizedRDSServerCount RDS-Servers" -Component "Farm Update" -Type Info
        $ChoosenHorizonFarmSettings.automated_farm_settings.pattern_naming_settings.max_number_of_rds_servers = $OptimizedRDSServerCount

        #Update Farm Configuration
        Invoke-RestMethod -Method Put -uri "$url/rest/inventory/v3/farms/$($ChoosenHorizonFarm.id)" -ContentType "application/json" -Headers (Get-HorizonHeader -accessToken $accessToken) -Body ($ChoosenHorizonFarmSettings | ConvertTo-Json -Depth 10)
        Write-log -Path $LogFilePath -Message "Changed!" -Component "Farm Update" -Type Info

    } catch {
        Write-Error ($_ | Out-String)
        Write-Log -Path $LogFilePath -Message ($_ | Out-String) -Component $MyInvocation.MyCommand.Name -Type Error
    }
}
#endregion

#region Remove RDS from Farm
#Remove RDS Server from given Farm when healthy and not having any sessions
If($OptimizedRDSServerCount -lt $ChoosenHorizonFarm.rds_server_count){
    for($i=0; $i -lt $ChoosenHorizonFarm.rds_server_count - 1; $i++){
        if($RDSServersInFarm[$i].status -eq "OK" -and $RDSServersInFarm[$i].session_count -eq 0 -and $RDSServersInFarm[$i].details.state -eq "AVAILABLE"){
            try {
                Write-log -Path $LogFilePath -Message "Attempt to remove $($RDSServersInFarm[$i].name) from Farm" -Component "Remove RDS from Farm" -Type Info
                Invoke-RestMethod -Method Post -uri "$url/rest/inventory/v1/farms/$($ChoosenHorizonFarm.id)/action/remove-rds-servers" -ContentType "application/json" -Headers (Get-HorizonHeader -accessToken $accessToken)  -Body (ConvertTo-Json @($($RDSServersInFarm[$i].id)))
                Write-log -Path $LogFilePath -Message "Removed!" -Component "Remove RDS from Farm" -Type Info

            } catch {
                Write-Error ($_ | Out-String)
                Write-Log -Path $LogFilePath -Message ($_ | Out-String) -Component $MyInvocation.MyCommand.Name -Type Error
            }

        }
    }
}
#endregion

#region Logout & Closing
$logOut = Close-HorizonConnection -url $url -accessToken $accessToken
Write-Log -Path $LogFilePath -Message "END - Over & Out" -Component "Logout & Closing" -Type Info
#endregion
