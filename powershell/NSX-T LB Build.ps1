function Get-NSXTAuthenticationHeaders {
<#
.SYNOPSIS
Generates HTTP Headers, including Authorization, for use with NSX-T API calls and vIDM.
.DESCRIPTION
The default functionality of Connect-NSXTServer in the PowerCLI module assumes local admin access only - not vIDM.
The output of this function given your credentials is the Authorization header(s) to make subsequent requests.
.PARAMETER Credential
The PSCredential or username/password to generate the headers from.
.EXAMPLE
$MyCred = Get-Credential -Message "My NSXT vIDM User Account in user@domain.com format"
$MyHeaders = Get-NSXTAuthenticationHeaders -Credential $MyCred

Generates headers for subsequent REST API calls with a vIDM User.
Note that you do not need to specify any particular endpoint with this function.
From a user perspective, it is probably best to embed this function call into your own functions, and just pass in the PSCredential object.
.OUTPUTS
Hashtable of HTTP Headers.
For any subsequent "Invoke-RestMethod" or "Invoke-WebRequest" calls, add the output of this function to the command with parameter -Headers
.NOTES
None
.LINK
None
#>
    param(
        [System.Management.Automation.PSCredential]$Credential
    )
    # The PowerCLI module doesn't support vIDM connections, so a custom function is needed.
    # Parse the username and check to see if there is an '@' symbol or not - if not, append "System Domain" for local account vIDM access.
    # The result of this function should be passed in to all future requests.
    <#
    if($Credential.UserName -notmatch "@") {
        Write-Warning "No domain was specified in the credential, so assuming it is for the `"System Domain`"..."
        $CredUser = "$($Credential.UserName)@System Domain"
    } else {
        $CredUser = $Credential.UserName
    }
    #>
    $CredUser = $Credential.UserName
    $CredPass = $Credential.GetNetworkCredential().Password
    $CredString = "$($CredUser):$($CredPass)"
    Write-Host "Generating Authentication headers for user [$($Credential.UserName)] ... " -ForegroundColor Cyan -NoNewline
    $Base64Creds = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($CredString))
    Write-Host "done." -ForegroundColor Green

    $Headers = @{}
    $Headers.Add("Content-Type","application/json")
    $Headers.Add("Accept","application/json")
    $Headers.Add("Authorization","Basic $Base64Creds")

    return $Headers
}

function New-NSXTOneArmLoadBalancer {
<#
.SYNOPSIS
Creates a Tier1 Gateway in a one-arm load balancer configuration.
.DESCRIPTION
Creates a Tier1 Gateway in a one-arm load balancer configuration.
This includes creation of the Gateway, a service interface, and a default static route for return traffic.
.PARAMETER Name
The name of the Tier1 Gateway. This value is also used to instantiate other pieces such as the service interface.
.PARAMETER Description
An optional description. If omitted a generic one is created based on the $Name value.
.PARAMETER EdgeCluster
Name of the Edge Cluster to associate the Tier1 Gateway to for traffic routing purposes. Just the name is required and the existence is validated.
.PARAMETER SegmentName
Name of the Logical Segment to use for this Tier1 Gateway, interface, and static route.
.PARAMETER IPAddress
The IP Address of the service interface to be allocated to the Tier1 Gateway. This is not a VIP for other services.
.PARAMETER NetmaskBits
The subnet mask, expressed in bits. Only values between 16 and 32 are accepted (but you could modify that if you wanted to I guess).
For example, a "16" is equivalent to 255.255.0.0, a "24" is equivalent to "255.255.255.0" and so on.
.PARAMETER Gateway
The default gateway for the static route to send traffic back through.
.PARAMETER NSXManager
The FQDN of the NSX-T Manager to execute the creation on.
.PARAMETER Credential
Your username/password credentials to pass to NSX-T. This must be a vIDM user.
If the vIDM user is in the local directory, omit the @domain.com portion of the account name.
.EXAMPLE
$MyCred = Get-Credential -Message "My NSXT vIDM User Account in user@domain.com format"

$MyTier1Gateway = @{
	Name = "VRA-Tier1"
	Description = "LB Gateway for vRA"
	EdgeCluster = "Edge-Cluster-Lab"
	SegmentName = "ComputeSegment01"
	IPAddress = 192.168.67.5 
	NetmaskBits = 24
	Gateway = 192.168.67.1
	NSXManager = nsxt.sprockit.local
	Credential = $MyCred
}

New-NSXTOneArmLoadBalancer @MyTier1Gateway

Creates a T1 Gateway with the given specifications.
.OUTPUTS
Object representing the newly created Tier-1 Gateway
.NOTES
None
.LINK
None
#>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [string]$Description,
        [Parameter(Mandatory=$true)][string]$EdgeCluster,
        [Parameter(Mandatory=$true)][string]$SegmentName,
        [Parameter(Mandatory=$true)][ipaddress]$IPAddress,
        [Parameter(Mandatory=$true)][ValidateRange(16,32)][int32]$NetmaskBits,
        [Parameter(Mandatory=$true)][ipaddress]$Gateway,
        [Parameter(Mandatory=$true)][string]$NSXManager,
        [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$Credential
    )
    # Basic Checks
    if(!$Description) {$Description = "Tier1 Gateway - $Name"}
    $Headers = Get-NSXTAuthenticationHeaders -Credential $Credential
    
    # Check to ensure the NSX-T Manager specified is resolvable in DNS and reachable on the current network.
    Write-Host "New-NSXTOneArmLoadBalancer :: Checking for NSX-T Manager [$NSXManager] ... " -NoNewline -ForegroundColor Cyan
    try {
        $NSXCheck = Test-NetConnection -ComputerName $NSXManager -InformationLevel Quiet
        if(!$NSXCheck) {
            Write-host "failed!"
            Write-Error "The NSX Manager [$NSXManager] you specified is not pinging. Please verify your network connectivity and try again!"
            break
        }
        Write-Host "success!" -ForegroundColor Green
    } catch {
        throw("There was an error attempting to ping the NSX Manager: $($_.Exception)")
    }

    # Start by searching for the Edge Gateway specified to associate to the T1.
    $EdgeClusterFound = $false
    Write-Host "New-NSXTOneArmLoadBalancer :: Checking for Edge Cluster [$EdgeCluster] ... " -NoNewline -ForegroundColor Cyan
    try {
        $EdgeClusters = Invoke-RestMethod -Method Get -Uri "https://$NSXManager/policy/api/v1/infra/sites/default/enforcement-points/default/edge-clusters" -Headers $Headers -ErrorAction Stop
        for($e=0;$e -lt $EdgeClusters.result_count;$e++) {
            # Find the Edge Cluster that matches the input
            if($EdgeClusters.results[$e].display_name -eq $EdgeCluster) {
                # Found it, assign and exit loop.
                $EdgeClusterId = $EdgeClusters.results[$e].id
                $EdgeClusterPath = $EdgeClusters.results[$e].path
                $EdgeClusterFound = $true
                Write-Host "found!" -ForegroundColor Green
                break
            }
        }
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd()
        $streamReader.Close()
        Write-Error "There was an error finding the Edge Cluster: $RequestError"
        
    }

    # Loop complete - check to see if there were any matches. If not, gracefully output and exit.
    if(!$EdgeClusterFound) {
        Write-Host "not found!" -ForegroundColor Yellow
        Write-Error "The Edge Cluster you specified [$EdgeCluster] was not found. Please specify an Edge Cluster that exists, and try again."
        break
    }


    # Check for the Segment specified to see if it exists. If so, get the path for later use.
    Write-Host "New-NSXTOneArmLoadBalancer :: Checking for Logical Segment [$SegmentName] ... " -NoNewline -ForegroundColor Cyan
    try {
        $SegmentCheck = Invoke-RestMethod -Method Get -Uri "https://$NSXManager/policy/api/v1/infra/segments/$SegmentName" -Headers $Headers -ErrorAction Stop
        $SegmentPath = $SegmentCheck.path
        Write-Host "found!" -ForegroundColor Green
    } catch {
        # This API call throws a 404 if the segment isn't found, so just echo it out and gracefully exit.
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd() | ConvertFrom-Json
        $streamReader.Close()
        Write-Error "There was an error finding the segment [$SegmentName]`nStatus: $($RequestError.httpStatus)`nError Message: $($RequestError.error_message)"
        break    
    }

    # Step 1 - Create a Tier 1 Gateway, not linked to a T0 directly so as to stay out of the data path. (This is a one-arm config, not transparent mode)
    $GatewaySpec = @{}
    $GatewaySpec.failover_mode = "NON_PREEMPTIVE"
    $GatewaySpec.enable_standby_relocation = $false
    $GatewaySpec.route_advertisement_types = @()
    $GatewaySpec.route_advertisement_types += "TIER1_LB_VIP"
    $GatewaySpec.route_advertisement_types += "TIER1_LB_SNAT"
    $GatewaySpec.force_whitelisting = $false
    $GatewaySpec.default_rule_logging = $False
    $GatewaySpec.disable_firewall = $false
    $GatewaySpec.resource_type = "Tier1"
    $GatewaySpec.id = $Name
    $GatewaySpec.display_name = $Name
    $GatewaySpec.description = $Description
    $GatewaySpec.type = "ISOLATED"
    # Convert the hashtable to a JSON string for the API call.
    $GatewayBody = $GatewaySpec | ConvertTo-Json
    try {
        Write-Host "New-NSXTOneArmLoadBalancer :: Creating Tier-1 Gateway [$Name] ... " -ForegroundColor Cyan -NoNewline
        $CreatedGateway = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/tier-1s/$Name" -Body $GatewayBody -Headers $Headers -ErrorAction Stop
        Write-Host "success!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd() | ConvertFrom-Json
        $streamReader.Close()
        throw("There was an error creating the Tier-1 Gateway [$Name] -- $RequestError")
    }

    # Step 2 - Gateway Created, now add the locale info pointing to the Edge Cluster. It will auto-distribute between 2 edge nodes.
    $LocaleSpec = @{}
    $LocaleSpec.edge_cluster_path = $EdgeClusterPath
    $LocaleBody = $LocaleSpec | ConvertTo-Json
    try {
        Write-Host "New-NSXTOneArmLoadBalancer :: Setting Tier-1 Gateway to use Edge Cluster [$EdgeCluster] ... " -ForegroundColor Cyan -NoNewline
        $UpdatedLocale = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/tier-1s/$Name/locale-services/default" -Body $LocaleBody -Headers $Headers -ErrorAction Stop
        Write-Host "success!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd() | ConvertFrom-Json
        $streamReader.Close()
        throw("There was an error setting the Tier-1 Gateway [$Name] to use Edge Cluster [$EdgeCluster] -- $RequestError")
    }

    # Step 3 - Add service interface with IP and subnet mask.
    [array]$IPAddresses = $IPAddress.IPAddressToString
    $Subnet = @{}
    $Subnet.prefix_len = $NetmaskBits
    $Subnet.ip_addresses = $IPAddresses
    [array]$Subnets += $Subnet
    
    $InterfaceSpec = @{}
    $InterfaceSpec.segment_path = $SegmentPath
    $InterfaceSpec.subnets = $Subnets
    $InterfaceBody = ConvertTo-Json -InputObject $InterfaceSpec -Depth 5

    try {
        Write-Host "New-NSXTOneArmLoadBalancer :: Adding Tier-1 Gateway Service Interface at $($IPAddress.IPAddressToString)/$NetmaskBits ... " -ForegroundColor Cyan -NoNewline
        $UpdatedInterface = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/tier-1s/$Name/locale-services/default/interfaces/$Name-ServiceInterface" -Body $InterfaceBody -Headers $Headers -ErrorAction Stop
        Write-Host "success!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd() | ConvertFrom-Json
        $streamReader.Close()
        throw("There was an error setting the Tier-1 Gateway [$Name] to use a service interface at [$($IPAddress.IPAddressToString)/$NetmaskBits] -- $RequestError")
    }

    # Step 4 - Interface added, now add static route and attach the next hop to that interface.
    $RouteSpec = @{}
    $RouteSpec.network = "0.0.0.0/0"
    $GatewayObject = @{}
    $GatewayObject.ip_address = $Gateway.IPAddressToString
    $GatewayObject.admin_distance = 1
    $RouteSpec.next_hops = @()
    $RouteSpec.next_hops += $GatewayObject
    $RouteBody = $RouteSpec | ConvertTo-Json
    try {
        Write-Host "New-NSXTOneArmLoadBalancer :: Adding Static Route for Tier-1 Gateway [$Name] for source NAT routing using gateway [$($Gateway.IPAddressToString)] ... " -ForegroundColor Cyan -NoNewline
        $UpdatedRoute = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/tier-1s/$Name/static-routes/$Name-DefaultRoute" -Body $RouteBody -Headers $Headers -ErrorAction Stop
        Write-Host "success!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd() | ConvertFrom-Json
        $streamReader.Close()
        throw("There was an error setting the Tier-1 Gateway [$Name] to use a service interface at [$($IPAddress.IPAddressToString)/$NetmaskBits] -- $RequestError")
    }

    # Step 5 - Retrieve the created static route to add the Service Interface Scope
    # You query all routes, get the one that matches by display_name, and get the ID.
    $StaticRoutes = Invoke-RestMethod -Method Get -Uri "https://$NSXManager/policy/api/v1/infra/tier-1s/$Name/static-routes" -Headers $Headers
    $StaticRouteObject = $StaticRoutes.results | Where-Object display_name -eq "$Name-DefaultRoute"
    $StaticRouteID = $StaticRouteObject.id

    # Add the updated scope.
    $StaticRouteScope = "/infra/tier-1s/$Name/locale-services/default/interfaces/$Name-ServiceInterface"
    Add-Member -Name "scope" -Value @($StaticRouteScope) -InputObject $StaticRouteObject.next_hops[0] -MemberType NoteProperty
    # Then, send a PUT request with the updated data.
    $StaticRouteBody = $StaticRouteObject | ConvertTo-Json -Depth 5
    try {
        Write-Host "New-NSXTOneArmLoadBalancer :: Updating static route next-hop to use the service interface ... " -ForegroundColor Cyan -NoNewline
        $StaticRouteUpdate = Invoke-RestMethod -Method Put -Uri "https://$NSXManager/policy/api/v1/infra/tier-1s/$Name/static-routes/$StaticRouteID" -Body $StaticRouteBody -Headers $Headers -ErrorAction Stop
        Write-Host "success!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd() | ConvertFrom-Json
        $streamReader.Close()
        throw("There was an error setting the next hop on the static route -- $RequestError")
    }
    Start-Sleep -Seconds 5
    # Test connectivity to the T1 gateway.
    $GatewayCheck = Test-NetConnection -ComputerName $IPAddress -InformationLevel Quiet
    if($GatewayCheck) {
        Write-Host "New-NSXTOneArmLoadBalancer :: Your one-arm load balancer gateway [$Name] pinged successfully! The next step is to attach a Load Balancer service/services to it." -ForegroundColor Green
    } else {
        Write-Warning "New-NSXTOneArmLoadBalancer :: The gateway was created using the API, but it was not pingable after a few seconds. You may need to manually verify!"
    }

    # Return object
    $OutputObject = Invoke-RestMethod -Method Get -Uri "https://$NSXManager/policy/api/v1/infra/tier-1s/$Name" -Headers $Headers
    return $OutputObject
}

function New-NSXTvRALBConfiguration {
<#
.SYNOPSIS
Creates a NSX-T Load Balancer configuration for vRealize Automation 8.
.DESCRIPTION
Creates all of the constructs needed to enable a Load Balanced vRA 8 installation.
Based on the official documentation.
.PARAMETER ProfileNamePrefix
A name to use in the creation of the various rules and settings.
.PARAMETER Tier1Gateway
The name of the Tier-1 Gateway to attach the load balancer services to.
If it doesn't exist, you can create one using the 'New-NSXTOneArmLoadBalancer' function!
.PARAMETER Servers
A list of the vRA appliance IP addresses.
.PARAMETER VirtualIP
The virtual IP address to be used for load balancing between the appliances.
.PARAMETER NSXManager
The FQDN of the NSX-T Manager to execute the creation on.
.PARAMETER Credential
Your username/password credentials to pass to NSX-T. This must be a vIDM user.
If the vIDM user is in the local directory, omit the @domain.com portion of the account name.
.EXAMPLE
$NSXCreds = Get-Credential -Message "My NSXT vIDM User Account in user@domain.com format"
$ServiceArgs = @{
    ProfileNamePrefix = "MyPrefix"
    Appliances = "192.168.1.1", "192.168.1.2", "192.168.1.3"
	VirtualIP = "192.168.67.10"
	NSXManager = "nsxt.sprockit.local"
	Credential = $NSXCreds
}
New-NSXTvRALBConfiguration @ServiceArgs

Creates the load balancer service and all related vRA 8.0 constructs.
.EXAMPLE
$NSXCreds = Get-Credential -Message "My NSXT vIDM User Account in user@domain.com format"
$ServiceArgs = @{
    ProfileNamePrefix = "MyPrefix"
    Appliances = "192.168.1.1", "192.168.1.2", "192.168.1.3"
	VirtualIP = "192.168.67.10"
	NSXManager = "nsxt.sprockit.local"
	Credential = $NSXCreds
    Tier1Gateway = "MyTier1Gateway"
}
New-NSXTvRALBConfiguration @ServiceArgs

Creates the load balancer service and all related vRA 8.0 constructs, and attaches it to the specified gateway.
.OUTPUTS
The New Load Balancer service object
.NOTES
None
.LINK
https://docs.vmware.com/en/vRealize-Automation/8.0/vRA_load-balancing_80.pdf
#>
    param(
        [Parameter(Mandatory=$true)][string]$ProfileNamePrefix,
        [Parameter(Mandatory=$true)][ipaddress[]]$Appliances,
        [Parameter(Mandatory=$true)][ipaddress]$VirtualIP,
        [Parameter(Mandatory=$true)][string]$NSXManager,
        [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$Credential,
        [string]$Tier1Gateway
    )
    # Setup user credentials.
    $Headers = Get-NSXTAuthenticationHeaders -Credential $Credential
    ##### Create a Load Balancer Service and assign to Tier-1 Gateway

    ##### Application Health Monitor
    $AppMonitorSpec = @{}
    $AppMonitorSpec.resource_type = "LBHttpMonitorProfile"
    $AppMonitorSpec.display_name = "$ProfileNamePrefix-VRA-HTTPS-HealthMonitor"
    $AppMonitorSpec.monitor_port = 8008
    $AppMonitorSpec.interval = 3
    $AppMonitorSpec.timeout = 10
    $AppMonitorSpec.fall_count = 3
    $AppMonitorSpec.request_method = "GET"
    $AppMonitorSpec.request_url = "/health"
    $AppMonitorSpec.request_version = "HTTP_VERSION_1_1"
    [array]$AppMonitorSpec.response_status_codes = 200
    $AppMonitorSpec.description = "HTTPS Health Monitor for $ProfileNamePrefix-VRA"
    $AppMonitorBody = $AppMonitorSpec | ConvertTo-Json -Depth 5

    # Create the Application Health Monitor via REST API.
    Write-Host "New-NSXTvRALBConfiguration :: Creating Application Monitor [$ProfileNamePrefix-VRA-HTTPS-HealthMonitor] ... " -NoNewline -ForegroundColor Cyan
    try {
        $HealthMonitor = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/lb-monitor-profiles/$ProfileNamePrefix-VRA-HTTPS-HealthMonitor" -Headers $Headers -Body $AppMonitorBody -ErrorAction Stop
        Write-Host "done!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd()
        $streamReader.Close()
        Write-Error "There was an error creating the Application Monitor [$ProfileNamePrefix-VRA-HTTPS-HealthMonitor] - $RequestError"
        break    
    }

    ##### Application Profile
    $AppProfileSpec = @{}
    $AppProfileSpec.resource_type = "LBFastTcpProfile"
    $AppProfileSpec.idle_timeout = 1800
    $AppProfileSpec.display_name = "$ProfileNamePrefix-VRA-HTTPS-AppProfile"
    $AppProfileSpec.close_timeout = 8
    $AppProfileBody = $AppProfileSpec | ConvertTo-Json -Depth 5
    
    Write-Host "New-NSXTvRALBConfiguration :: Creating Application Profile [$ProfileNamePrefix-VRA-HTTPS-AppProfile] ... " -NoNewline -ForegroundColor Cyan
    try {
        $AppProfileResult = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/lb-app-profiles/$ProfileNamePrefix-VRA-HTTPS-AppProfile" -Headers $Headers -Body $AppProfileBody -ErrorAction Stop
        Write-Host "done!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd()
        $streamReader.Close()
        Write-Error "There was an error creating the Application Profile [$ProfileNamePrefix-VRA-HTTPS-AppProfile] - $RequestError"
        break    
    }

    ##### Persistence Profile
    $PersistenceSpec = @{}
    $PersistenceSpec.display_name = "$ProfileNamePrefix-VRA-Persistence"
    $PersistenceSpec.description = "Persistence Profile for $ProfileNamePrefix-VRA"
    $PersistenceSpec.resource_type = "LBSourceIpPersistenceProfile"
    $PersistenceSpec.timeout = 1500
    $PersistenceSpec.purge = "FULL"
    $PersistenceBody = $PersistenceSpec | ConvertTo-Json -Depth 5

    Write-Host "New-NSXTvRALBConfiguration :: Creating App Persistence Profile [$ProfileNamePrefix-VRA-Persistence] ... " -NoNewline -ForegroundColor Cyan
    try {
        $PersistenceResult = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/lb-persistence-profiles/$ProfileNamePrefix-VRA-Persistence" -Headers $Headers -Body $PersistenceBody -ErrorAction Stop
        Write-Host "done!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd()
        $streamReader.Close()
        Write-Error "There was an error creating the App Persistence Profile [$ProfileNamePrefix-VRA-Persistence] - $RequestError"
        break    
    }

    ##### Server Pool
    $PoolSpec = @{}
    $PoolSpec.display_name = "$ProfileNamePrefix-VRA-ServerPool"
    $PoolSpec.description = "Server Pool for $ProfileNamePrefix-VRA"
    [array]$PoolSpec.active_monitor_paths = "/infra/lb-monitor-profiles/$ProfileNamePrefix-VRA-HTTPS-HealthMonitor"
    $PoolSpec.snat_translation = @{}
    $PoolSpec.snat_translation.type = "LBSnatAutoMap"
    $PoolSpec.members = @()
    foreach($Appliance in $Appliances) {
        $LBMember = @{}
        $LBMember.admin_state = "ENABLED"
        $LBMember.display_name = "vRA Appliance - $($Appliance.IPAddressToString)"
        $LBMember.ip_address = $Appliance.IPAddressToString
        $LBMember.port = 443
        $PoolSpec.members += $LBMember
    }
    $PoolSpec.algorithm = "LEAST_CONNECTION"
    $PoolSpec.min_active_members = 1
    $PoolBody = $PoolSpec | ConvertTo-Json -Depth 5

    Write-Host "New-NSXTvRALBConfiguration :: Creating Server Pool [$ProfileNamePrefix-VRA-ServerPool] ... " -NoNewline -ForegroundColor Cyan
    try {
        $PoolResult = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/lb-pools/$ProfileNamePrefix-VRA-ServerPool" -Headers $Headers -Body $PoolBody -ErrorAction Stop
        Write-Host "done!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd()
        $streamReader.Close()
        Write-Error "There was an error creating the Server Pool [$ProfileNamePrefix-VRA-ServerPool] - $RequestError"
        break    
    }
 
    ##### Load Balancer Services
    # If the Tier-1 Gateway is not specified, do not include it in the specification, so it can be attached manually later.
    $LBSpec = @{}
    if($Tier1Gateway) { $LBSpec.connectivity_path = "/infra/tier-1s/$Tier1Gateway" }
    $LBSpec.enabled = $true
    $LBSpec.size = "SMALL"
    $LBSpec.resource_type = "LBService"
    $LBSpec.display_name = "$ProfileNamePrefix-VRA-LBService"
    $LBSpec.description = "Load Balancer Service - $ProfileNamePrefix"

    $LBBody = $LBSpec | ConvertTo-Json -Depth 5
    Write-Host "New-NSXTvRALBConfiguration :: Creating Load Balancer Service [$ProfileNamePrefix-VRA-LBService] ... " -NoNewline -ForegroundColor Cyan
    try {
        $LBResult = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/lb-services/$ProfileNamePrefix-VRA-LBService" -Headers $Headers -Body $LBBody -ErrorAction Stop
        Write-Host "done!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd()
        $streamReader.Close()
        Write-Error "There was an error creating the Load Balancer Service [$ProfileNamePrefix-VRA-LBService] - $RequestError"
        break    
    }
 
    ##### Virtual Server (VIP) - create and attach to the LB Service.
    $VirtualServerSpec = @{}
    $VirtualServerSpec.display_name = "$ProfileNamePrefix-VRA-VirtualServer"
    $VirtualServerSpec.description = "Virtual Server (VIP) for $ProfileNamePrefix-VRA"
    [array]$VirtualServerSpec.ports = 443
    [array]$VirtualServerSpec.default_pool_member_ports = 443
    $VirtualServerSpec.application_profile_path = "/infra/lb-app-profiles/$ProfileNamePrefix-VRA-HTTPS-AppProfile"
    $VirtualServerSpec.enabled = $true
    $VirtualServerSpec.ip_address = $VirtualIP.IPAddressToString
    $VirtualServerSpec.lb_persistence_profile_path = "/infra/lb-persistence-profiles/$ProfileNamePrefix-VRA-Persistence"
    $VirtualServerSpec.lb_service_path = "/infra/lb-services/$ProfileNamePrefix-VRA-LBService"
    $VirtualServerSpec.pool_path = "/infra/lb-pools/$ProfileNamePrefix-VRA-ServerPool"
    $VirtualServerSpec.resource_type = "LBVirtualServer"
    $VirtualServerBody = $VirtualServerSpec | ConvertTo-Json -Depth 5

    Write-Host "New-NSXTvRALBConfiguration :: Creating Virtual Server [$ProfileNamePrefix-VRA-VirtualServer] and associating it with Load Balancer [$ProfileNamePrefix-VRA-LBService] ... " -NoNewline -ForegroundColor Cyan
    try {
        $VirtualServerResult = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/lb-virtual-servers/$ProfileNamePrefix-VRA-VirtualServer" -Headers $Headers -Body $VirtualServerBody -ErrorAction Stop
        Write-Host "done!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd()
        $streamReader.Close()
        Write-Error "There was an error creating the Virtual Server [$ProfileNamePrefix-VRA-VirtualServer] - $RequestError"
        break    
    }

    # Output
    $Output = Invoke-RestMethod -Method Get -Uri "https://$NSXManager/policy/api/v1/infra/lb-services/$ProfileNamePrefix-VRA-LBService" -Headers $Headers -ErrorAction Stop
    return $Output

}

function New-NSXTvIDMLBConfiguration {
<#
.SYNOPSIS
Creates a NSX-T Load Balancer configuration for VMware Identity Manager 3.3.1 or higher.
.DESCRIPTION
Creates all of the constructs needed to enable a Load Balanced vIDM cluster.
Based on the official documentation.
.PARAMETER ProfileNamePrefix
A name to use in the creation of the various rules and settings.
.PARAMETER Tier1Gateway
The name of the Tier-1 Gateway to attach the load balancer services to.
If it doesn't exist, you can create one using the 'New-NSXTOneArmLoadBalancer' function!
.PARAMETER Servers
A list of the vIDM appliance IP addresses.
.PARAMETER VirtualIP
The virtual IP address to be used for load balancing between the appliances.
.PARAMETER NSXManager
The FQDN of the NSX-T Manager to execute the creation on.
.PARAMETER Credential
Your username/password credentials to pass to NSX-T. This must be a vIDM user.
If the vIDM user is in the local directory, omit the @domain.com portion of the account name.
.EXAMPLE
$NSXCreds = Get-Credential -Message "My NSXT vIDM User Account in user@domain.com format"
$ServiceArgs = @{
    ProfileNamePrefix = "MyPrefix"
    Appliances = "192.168.2.1", "192.168.2.2", "192.168.2.3"
	VirtualIP = "192.168.2.10"
	NSXManager = "nsxt.sprockit.local"
	Credential = $NSXCreds
}
New-NSXTvRALBConfiguration @ServiceArgs

Creates the load balancer service and all related vIDM constructs.
.OUTPUTS
The New Load Balancer service object
.NOTES
None
.LINK
https://docs.vmware.com/en/vRealize-Automation/8.0/vRA_load-balancing_80.pdf
.LINK
https://docs.vmware.com/en/VMware-Workspace-ONE-Access/19.03/vidm-install/GUID-959E0EFF-AF1F-4479-A19C-98BAF813E73C.html
#>
    param(
        [Parameter(Mandatory=$true)][string]$ProfileNamePrefix,
        [Parameter(Mandatory=$true)][ipaddress[]]$Appliances,
        [Parameter(Mandatory=$true)][ipaddress]$VirtualIP,
        [Parameter(Mandatory=$true)][string]$NSXManager,
        [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$Credential,
        [string]$Tier1Gateway
    )
    # Setup user credentials.
    $Headers = Get-NSXTAuthenticationHeaders -Credential $Credential
    ##### Create a Load Balancer Service and assign to Tier-1 Gateway

    ##### Application Health Monitor
    $AppMonitorSpec = @{}
    $AppMonitorSpec.resource_type = "LBHttpMonitorProfile"
    $AppMonitorSpec.display_name = "$ProfileNamePrefix-VRA-HTTPS-HealthMonitor"
    $AppMonitorSpec.monitor_port = 8008
    $AppMonitorSpec.interval = 3
    $AppMonitorSpec.timeout = 10
    $AppMonitorSpec.fall_count = 3
    $AppMonitorSpec.request_method = "GET"
    $AppMonitorSpec.request_url = "/health"
    $AppMonitorSpec.request_version = "HTTP_VERSION_1_1"
    [array]$AppMonitorSpec.response_status_codes = 200
    $AppMonitorSpec.description = "HTTPS Health Monitor for $ProfileNamePrefix-VRA"
    $AppMonitorBody = $AppMonitorSpec | ConvertTo-Json -Depth 5

    # Create the Application Health Monitor via REST API.
    Write-Host "New-NSXTvRALBConfiguration :: Creating Application Monitor [$ProfileNamePrefix-VRA-HTTPS-HealthMonitor] ... " -NoNewline -ForegroundColor Cyan
    try {
        $HealthMonitor = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/lb-monitor-profiles/$ProfileNamePrefix-VRA-HTTPS-HealthMonitor" -Headers $Headers -Body $AppMonitorBody -ErrorAction Stop
        Write-Host "done!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd()
        $streamReader.Close()
        Write-Error "There was an error creating the Application Monitor [$ProfileNamePrefix-VRA-HTTPS-HealthMonitor] - $RequestError"
        break    
    }

    ##### Application Profile
    $AppProfileSpec = @{}
    $AppProfileSpec.resource_type = "LBFastTcpProfile"
    $AppProfileSpec.idle_timeout = 1800
    $AppProfileSpec.display_name = "$ProfileNamePrefix-VRA-HTTPS-AppProfile"
    $AppProfileSpec.close_timeout = 8
    $AppProfileBody = $AppProfileSpec | ConvertTo-Json -Depth 5
    
    Write-Host "New-NSXTvRALBConfiguration :: Creating Application Profile [$ProfileNamePrefix-VRA-HTTPS-AppProfile] ... " -NoNewline -ForegroundColor Cyan
    try {
        $AppProfileResult = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/lb-app-profiles/$ProfileNamePrefix-VRA-HTTPS-AppProfile" -Headers $Headers -Body $AppProfileBody -ErrorAction Stop
        Write-Host "done!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd()
        $streamReader.Close()
        Write-Error "There was an error creating the Application Profile [$ProfileNamePrefix-VRA-HTTPS-AppProfile] - $RequestError"
        break    
    }

    ##### Persistence Profile
    $PersistenceSpec = @{}
    $PersistenceSpec.display_name = "$ProfileNamePrefix-VRA-Persistence"
    $PersistenceSpec.description = "Persistence Profile for $ProfileNamePrefix-VRA"
    $PersistenceSpec.resource_type = "LBSourceIpPersistenceProfile"
    $PersistenceSpec.timeout = 1500
    $PersistenceSpec.purge = "FULL"
    $PersistenceBody = $PersistenceSpec | ConvertTo-Json -Depth 5

    Write-Host "New-NSXTvRALBConfiguration :: Creating App Persistence Profile [$ProfileNamePrefix-VRA-Persistence] ... " -NoNewline -ForegroundColor Cyan
    try {
        $PersistenceResult = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/lb-persistence-profiles/$ProfileNamePrefix-VRA-Persistence" -Headers $Headers -Body $PersistenceBody -ErrorAction Stop
        Write-Host "done!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd()
        $streamReader.Close()
        Write-Error "There was an error creating the App Persistence Profile [$ProfileNamePrefix-VRA-Persistence] - $RequestError"
        break    
    }

    ##### Server Pool
    $PoolSpec = @{}
    $PoolSpec.display_name = "$ProfileNamePrefix-VRA-ServerPool"
    $PoolSpec.description = "Server Pool for $ProfileNamePrefix-VRA"
    [array]$PoolSpec.active_monitor_paths = "/infra/lb-monitor-profiles/$ProfileNamePrefix-VRA-HTTPS-HealthMonitor"
    $PoolSpec.snat_translation = @{}
    $PoolSpec.snat_translation.type = "LBSnatAutoMap"
    $PoolSpec.members = @()
    foreach($Appliance in $Appliances) {
        $LBMember = @{}
        $LBMember.admin_state = "ENABLED"
        $LBMember.display_name = "vRA Appliance - $($Appliance.IPAddressToString)"
        $LBMember.ip_address = $Appliance.IPAddressToString
        $LBMember.port = 443
        $PoolSpec.members += $LBMember
    }
    $PoolSpec.algorithm = "LEAST_CONNECTION"
    $PoolSpec.min_active_members = 1
    $PoolBody = $PoolSpec | ConvertTo-Json -Depth 5

    Write-Host "New-NSXTvRALBConfiguration :: Creating Server Pool [$ProfileNamePrefix-VRA-ServerPool] ... " -NoNewline -ForegroundColor Cyan
    try {
        $PoolResult = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/lb-pools/$ProfileNamePrefix-VRA-ServerPool" -Headers $Headers -Body $PoolBody -ErrorAction Stop
        Write-Host "done!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd()
        $streamReader.Close()
        Write-Error "There was an error creating the Server Pool [$ProfileNamePrefix-VRA-ServerPool] - $RequestError"
        break    
    }
 
    ##### Load Balancer Services
    # If the Tier-1 Gateway is not specified, do not include it in the specification, so it can be attached manually later.
    $LBSpec = @{}
    if($Tier1Gateway) { $LBSpec.connectivity_path = "/infra/tier-1s/$Tier1Gateway" }
    $LBSpec.enabled = $true
    $LBSpec.size = "SMALL"
    $LBSpec.resource_type = "LBService"
    $LBSpec.display_name = "$ProfileNamePrefix-VRA-LBService"
    $LBSpec.description = "Load Balancer Service - $ProfileNamePrefix"

    $LBBody = $LBSpec | ConvertTo-Json -Depth 5
    Write-Host "New-NSXTvRALBConfiguration :: Creating Load Balancer Service [$ProfileNamePrefix-VRA-LBService] ... " -NoNewline -ForegroundColor Cyan
    try {
        $LBResult = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/lb-services/$ProfileNamePrefix-VRA-LBService" -Headers $Headers -Body $LBBody -ErrorAction Stop
        Write-Host "done!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd()
        $streamReader.Close()
        Write-Error "There was an error creating the Load Balancer Service [$ProfileNamePrefix-VRA-LBService] - $RequestError"
        break    
    }
 
    ##### Virtual Server (VIP) - create and attach to the LB Service.
    $VirtualServerSpec = @{}
    $VirtualServerSpec.display_name = "$ProfileNamePrefix-VRA-VirtualServer"
    $VirtualServerSpec.description = "Virtual Server (VIP) for $ProfileNamePrefix-VRA"
    [array]$VirtualServerSpec.ports = 443
    [array]$VirtualServerSpec.default_pool_member_ports = 443
    $VirtualServerSpec.application_profile_path = "/infra/lb-app-profiles/$ProfileNamePrefix-VRA-HTTPS-AppProfile"
    $VirtualServerSpec.enabled = $true
    $VirtualServerSpec.ip_address = $VirtualIP.IPAddressToString
    $VirtualServerSpec.lb_persistence_profile_path = "/infra/lb-persistence-profiles/$ProfileNamePrefix-VRA-Persistence"
    $VirtualServerSpec.lb_service_path = "/infra/lb-services/$ProfileNamePrefix-VRA-LBService"
    $VirtualServerSpec.pool_path = "/infra/lb-pools/$ProfileNamePrefix-VRA-ServerPool"
    $VirtualServerSpec.resource_type = "LBVirtualServer"
    $VirtualServerBody = $VirtualServerSpec | ConvertTo-Json -Depth 5

    Write-Host "New-NSXTvRALBConfiguration :: Creating Virtual Server [$ProfileNamePrefix-VRA-VirtualServer] and associating it with Load Balancer [$ProfileNamePrefix-VRA-LBService] ... " -NoNewline -ForegroundColor Cyan
    try {
        $VirtualServerResult = Invoke-RestMethod -Method Patch -Uri "https://$NSXManager/policy/api/v1/infra/lb-virtual-servers/$ProfileNamePrefix-VRA-VirtualServer" -Headers $Headers -Body $VirtualServerBody -ErrorAction Stop
        Write-Host "done!" -ForegroundColor Green
    } catch {
        Write-Host "failed!" -ForegroundColor Red
        # Capture the response
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $RequestError = $streamReader.ReadToEnd()
        $streamReader.Close()
        Write-Error "There was an error creating the Virtual Server [$ProfileNamePrefix-VRA-VirtualServer] - $RequestError"
        break    
    }

    # Output
    $Output = Invoke-RestMethod -Method Get -Uri "https://$NSXManager/policy/api/v1/infra/lb-services/$ProfileNamePrefix-VRA-LBService" -Headers $Headers -ErrorAction Stop
    return $Output

}

