If (-Not (Get-Command -Name 'Get-NetIPAddress' -ErrorAction Ignore -WarningAction Ignore)) # For backwards-compatibility with OSes that does not have this CmdLet
{

    Function Get-NetIPAddress 
    {
        Param 
        (
            [Parameter(
                Mandatory         = $False,
                HelpMessage       = "Filter network interfaces.",
                Position          = 0,
                ValueFromPipeline = $True
                )
            ]
            [System.String[]] $InterfaceAlias,
            [Parameter(
                Mandatory         = $False,
                HelpMessage       = "Filter address families.",
                Position          = 0,
                ValueFromPipeline = $True
                )
            ]
            [System.String[]] $AddressFamily = 'IPv4'
        ) # Param

        Begin
        {
            $AddressLines = $(netsh.exe interface ipv4 show addresses) -Replace '\s{2,}', '' -Split '\n' | Where-Object {-Not [System.String]::IsNullOrEmpty($_)}
            $Addresses = @()
        } # Begin

        Process
        {
            For ($I = 0; $I -Lt $AddressLines.Count; $I++)
            {
                If ($AddressLines[$I] -Match '^Configuration for interface "')
                {
                    $InterfaceAlias = "$($AddressLines[$I] -Replace '^Configuration for interface "', '' -Replace '"$', '')"
                    $DHCPEnabled = If ($AddressLines[($I+1)] -Replace '^DHCP enabled:', '' -Eq 'Yes'){$True}Else{$False}
                    $IPAddress = $AddressLines[($I+2)] -Replace '^IP Address:', ''
                    If ($IPAddress -Match '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' -And $IPAddress -NotMatch '^169\.254\.')
                    {
                        $Object = New-Object PSCustomObject
                        $Object | Add-Member -MemberType NoteProperty -Name InterfaceAlias -Value "$($InterfaceAlias)"
                        $Object | Add-Member -MemberType NoteProperty -Name DHCPEnabled -Value $DHCPEnabled
                        $Object | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress
                        $Addresses += $Object
                    } # If
                } # If
            } # For
        } # Process

        End
        {
            Return $Addresses
        } # End
    } # If

} # If

Function Get-GPUDriverVersion
{
    Begin
    {
        $QuickSearch = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe", "C:\Program Files (x86)\NVIDIA Corporation\NVSMI\nvidia-smi.exe", "C:\Windows\System32\nvidia-smi.exe", "C:\Windows\System32\DriverStore\FileRepository\nvhd.inf*\nvidia-smi.exe"
        $NVSMI = $QuickSearch | Where-Object {(Test-Path -Path $_) -Eq "$True"} | Select-Object -First 1 -Unique | Get-Item | Select-Object -ExpandProperty FullName
    } # Begin

    Process
    {
        #
    } # Process

    End
    {
        If (-Not $NVSMI){$NVSMI = Get-ChildItem -Path "$($env:SystemDrive)\" -Directory | Where-Object -FilterScript {$_.Name -Like "Program Files*" -Or $_.Name -Eq 'Windows'} | Get-ChildItem -Recurse -Filter "nvidia-smi.exe" | Select-Object -ExpandProperty FullName -First 1}
        $DrvV = (. $NVSMI --query-gpu=driver_version --format=csv |findstr /i /v "driver_version") -Replace "\s","" |sort | select -f 1
        Return $DrvV
    } # End
} # Function

Function Get-FQDNHostName ()
{
	$Domain = Get-WmiObject -Class Win32_ComputerSystem -Property Domain | Select-Object -ExpandProperty Domain
	$HostName = Get-WmiObject -Class Win32_ComputerSystem -Property Name | Select-Object -ExpandProperty Name
	
    Return "$($HostName).$($Domain)"
} # Function

Function Size-ToString ([Double] $Size)
{
	$Count = 0
	While ($Size -Ge 1024)
	{
		If ($ExecutionContext.SessionState.LanguageMode -Eq "FullLanguage")
        {
            $Size = ([Math]::Round($Size/1024, 2))
        }
        Else
        {
            $Size = $Size/1024
        } # If
		$Count++
	} # While
	Switch ($Count)
	{
		0 { $Ext = "B" }; 1 { $Ext = "KiB" }; 2 { $Ext = "MiB" }; 3 { $Ext = "GiB" }; 4 { $Ext = "TiB" }; 5 { $Ext = "PiB" }; 6 { $Ext = "EiB" }; 7 { $Ext = "ZiB" }; 8 { $Ext = "YiB" }; Default { $Ext = "WTF!?" }
	} # Switch
    If ($ExecutionContext.SessionState.LanguageMode -Ne "FullLanguage" -And $Size -Match "[0-9]{0,4}.[5-9]")
    {
        [Int] $Size = [Int] $Size + 1
    }
    ElseIf ($ExecutionContext.SessionState.LanguageMode -Ne "FullLanguage")
    {
        $Size = [Int] $Size
    } # If
	Return "$($Size) $Ext"
} # Function

# Set PSReadLineOptions
$PSReadLine = Get-Module -Name PSReadLine
If ($PSReadLine -And $PSReadLine.Version.Minor -Ge 2)
{
	Set-PSReadLineOption -Color @{
		"Command" = [ConsoleColor]::Green
		"Parameter" = [ConsoleColor]::Gray
		"Operator" = [ConsoleColor]::Magenta
		"Variable" = [ConsoleColor]::White
		"String" = [ConsoleColor]::Yellow
		"Number" = [ConsoleColor]::Blue
		"Type" = [ConsoleColor]::Cyan
		"Comment" = [ConsoleColor]::DarkCyan
		"InlinePrediction" = "#AC2080"
	}
    If ($ExecutionContext.Host.Version -Ge $([Version] "7.2.0"))
    {
        Set-PSReadLineOption -PredictionViewStyle 'ListView' -PredictionSource 'HistoryAndPlugin'
    }
    Else
    {
	    Set-PSReadLineOption -PredictionViewStyle 'ListView' -PredictionSource 'History'
    } # If
}
ElseIf ($PSReadLine)
{
	Set-PSReadLineOption -Color @{
		"Command" = [ConsoleColor]::Green
		"Parameter" = [ConsoleColor]::Gray
		"Operator" = [ConsoleColor]::Magenta
		"Variable" = [ConsoleColor]::White
		"String" = [ConsoleColor]::Yellow
		"Number" = [ConsoleColor]::Blue
		"Type" = [ConsoleColor]::Cyan
		"Comment" = [ConsoleColor]::DarkCyan
	}
} # If

# Get System information
$GPUs = [System.Array] (Get-WmiObject -Class Win32_VideoController -Property Name | Select-Object -ExpandProperty Name)
$GPUs = [System.Array] ($GPUs | ForEach-Object {$Split = $_ -Split '\s' ;$Obj = New-Object PSCustomObject; $Obj | Add-Member -MemberType NoteProperty -Name Vendor -Value $($Split[0]); $Obj | Add-Member -MemberType NoteProperty -Name Model -Value $(($Split[(1..($Split.Count-1))] -Join ' ')); $Obj})
$SoundDevs = [System.Array] (Get-WmiObject -Class Win32_SoundDevice -Property Manufacturer,ProductName)
$OS = Get-CimInstance -ClassName Win32_OperatingSystem -Property LastBootUpTime | Select-Object -ExpandProperty LastBootUpTime
$UpTime = (Get-Date) - $OS
$HotFix = Get-HotFix | Sort-Object -Property InstalledOn -Descending -ErrorAction Ignore -WarningAction Ignore | Select-Object -First 1 -ExpandProperty InstalledOn | Get-Date
$IPv4String = ''
$IPv4Interfaces = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Ignore -WarningAction Ignore | Where-Object -FilterScript {$_.InterfaceAlias -NotLike "Loopback*"} | Where-Object -FilterScript {$_.IPAddress -NotLike "169.254.*"})
ForEach ($IPv4Interface In $IPv4Interfaces)
{
    If ((Get-Command -Name Get-NetRoute) -And (Get-Command -Name Get-DnsClientServerAddress))
    {
        $IPv4String += "@{$($IPv4Interface.InterfaceAlias)=$($IPv4Interface.IPAddress); GW=$($($IPv4Interface | Get-NetRoute -AddressFamily IPv4 | Select-Object -ExpandProperty NextHop) -Ne '0.0.0.0' | Select-Object -Unique -First 1); DNS=@($(($IPv4Interface | Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses | ForEach-Object {"$($_)$(If (Resolve-DnsName -Name $_ -Type PTR -ErrorAction Ignore -WarningAction Ignore){"[$(Resolve-DnsName -Name $_ -Type PTR -ErrorAction Ignore -WarningAction Ignore | Select-Object -ExpandProperty NameHost -ErrorAction Ignore -WarningAction Ignore)]"})"}) -Join '; '))} "
    }
    Else
    {
        $IPv4String += "@{$($IPv4Interface.InterfaceAlias)=$($IPv4Interface.IPAddress)} "
    } # If
} # ForEach
If ($IPv4String.Length -Gt ([System.Console]::WindowWidth - 3 - 55))
{
    $IPv4String = $IPv4String.SubString(0, ([System.Console]::WindowWidth - 3 - 55))
    $IPv4String += "..."
} # If

Clear-Host; Write-Host
# Start line 1
'                               %        ' -Split '' | % {Write-Host -NoNewLine -Object $_ -ForeGroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}; 
"Uptime:        " -Split '' | % {Write-Host -NoNewLine -Object $_; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$("{0:dd}d:{0:hh}h:{0:mm}m:{0:ss}s" -f ($UpTime))" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor White -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
Write-Host
# End line 1

# Start line 2
'                           #####        ' -Split '' | % {Write-Host -NoNewLine -Object $_ -ForeGroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}; 
"User:          " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$($env:USERNAME)@$(If ($env:USERDNSDOMAIN){$env:USERDNSDOMAIN}Else{$env:USERDOMAIN})" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Green -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
Write-Host
# End line 2

# Start line 3
'                       #########        ' -Split '' | % {Write-Host -NoNewLine -Object $_ -ForeGroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}; 
"Host:          " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$(Get-FQDNHostName)$(If ((Get-WmiObject -Class Win32_ComputerSystem -Property Model | Select-Object -ExpandProperty Model) -NotLike "System*" -And (Get-WmiObject -Class Win32_ComputerSystem -Property Model | Select-Object -ExpandProperty Model) -NotLike "All Series*"){" [Model: $(Get-WmiObject -Class Win32_ComputerSystem -Property Model | Select-Object -ExpandProperty Model)$(If ((Get-WmiObject -Class Win32_ComputerSystemProduct -Property IdentifyingNumber | Select-Object -ExpandProperty IdentifyingNumber) -NotLike "System*"){"; Serial: $(Get-WmiObject -Class Win32_ComputerSystemProduct -Property IdentifyingNumber | Select-Object -ExpandProperty IdentifyingNumber)"})]"}Else{" [Model: $(Get-WmiObject -Class Win32_BaseBoard -Property Product -ErrorAction Ignore -WarningAction Ignore | Select-Object -ExpandProperty Product)$(If ((Get-WmiObject -Class Win32_ComputerSystemProduct -Property IdentifyingNumber | Select-Object -ExpandProperty IdentifyingNumber) -NotLike "System*"){"; Serial: $(Get-WmiObject -Class Win32_ComputerSystemProduct -Property IdentifyingNumber | Select-Object -ExpandProperty IdentifyingNumber)"})]"})" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor DarkCyan -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
Write-Host
# End line 3

# Start line 4
'    #             ##############        ' -Split '' | % {Write-Host -NoNewLine -Object $_ -ForeGroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}; 
"OS:            " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$((Get-WmiObject -Class Win32_OperatingSystem -Property Caption | Select-Object -ExpandProperty Caption) -Replace '^Microsoft\s', '') [$(Get-WmiObject -Class Win32_OperatingSystem -Property Version | Select-Object -ExpandProperty Version)]" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Cyan -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
Write-Host
# End line 4

# Start line 5
'    #####         ##############        ' -Split '' | % {Write-Host -NoNewLine -Object $_ -ForeGroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}; 
"InstallDate:   " -Split '' | ForEach-Object {Write-Host -Object $_  -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$(Get-CimInstance -ClassName Win32_OperatingSystem -Property InstallDate | Select-Object -ExpandProperty InstallDate | Get-Date -UFormat '%Y/%m/%d %r %Z')" -Split '' | ForEach-Object {Write-Host -Object $_  -ForegroundColor Gray -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
Write-Host
# End line 5

# Start line 6
'    ##########    ##############        ' -Split '' | % {Write-Host -NoNewLine -Object $_ -ForeGroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}; 
"LastUpdated:   " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; ; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
If ($HotFix -Ge (Get-Date).AddMonths(-1))
{
    "$($HotFix | Get-Date -UFormat '%Y/%m/%d %r %Z')" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Green -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
}
ElseIf ($HotFix -Ge (Get-Date).AddMonths(-3))
{
    "$($HotFix | Get-Date -UFormat '%Y/%m/%d %r %Z')" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Yellow -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
}
Else
{
    "$($HotFix | Get-Date -UFormat '%Y/%m/%d %r %Z')" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Red -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
} # If
Write-Host
# End line 6

# Start line 7
'    ##########    ##############        ' -Split '' | % {Write-Host -NoNewLine -Object $_ -ForeGroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}; 
"Processor(s):  " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
If ((Get-WmiObject -Class Win32_Processor -Property Name | Select-Object -ExpandProperty Name -Unique) -Match 'Intel')
{
    "$(Get-WmiObject -Class Win32_Processor -Property Name | Measure-Object | Select-Object -ExpandProperty Count)x $(Get-WmiObject -Class Win32_Processor -Property Name | Select-Object -ExpandProperty Name -Unique)" -Replace ' {1,}$', '' -Replace '\s{2,}', ' ' -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Blue -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
}
ElseIf ((Get-WmiObject -Class Win32_Processor -Property Name | Select-Object -ExpandProperty Name -Unique) -Match 'AMD')
{
    "$(Get-WmiObject -Class Win32_Processor -Property Name | Measure-Object | Select-Object -ExpandProperty Count)x $(Get-WmiObject -Class Win32_Processor -Property Name | Select-Object -ExpandProperty Name -Unique)" -Replace ' {1,}$', '' -Replace '\s{2,}', ' ' -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Red -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
} # If
Write-Host
# End line 7

# Start line 8
'    ##########    ############          ' -Split '' | % {Write-Host -NoNewLine -Object $_ -ForeGroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}; 
"Cores/Threads: " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$(Get-WmiObject -Class Win32_Processor -Property NumberOfCores | Select-Object -ExpandProperty NumberOfCores | Measure-Object -Sum | Select-Object -ExpandProperty Sum)c/$(Get-WmiObject -Class Win32_Processor -Property NumberOfLogicalProcessors | Select-Object -ExpandProperty NumberOfLogicalProcessors | Measure-Object -Sum | Select-Object -ExpandProperty Sum)t" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor DarkCyan -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
Write-Host
# End line 8

# Start line 9
'       #######    #######               ' -Split '' | % {Write-Host -NoNewLine -Object $_ -ForeGroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}; 
"Memory:        " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$(Size-ToString (Get-WmiObject -Class Win32_PhysicalMemory -Property * | Select-Object -Property Capacity | Measure-Object -Property Capacity -Sum | Select-Object -ExpandProperty Sum)) ($($Capacities = Get-WmiObject -Class Win32_PhysicalMemory -Property Capacity | Select-Object -ExpandProperty Capacity -Unique | Sort-Object; $Capacities | ForEach-Object {$Str = ''; $Str += Get-WmiObject -Class Win32_PhysicalMemory -Filter "Capacity=$($_)" | Measure-Object | Select-Object -ExpandProperty Count; $Str += ' x '; $Str += Size-ToString -Size ((Get-WmiObject -Class Win32_PhysicalMemory  -Filter "Capacity=$($_)" | Select-Object -ExpandProperty Capacity | Measure-Object -Sum | Select-Object -ExpandProperty Sum)/(Get-WmiObject -Class Win32_PhysicalMemory -Filter "Capacity=$($_)" | Measure-Object | Select-Object -ExpandProperty Count)); $Str}))$(If ((Get-WmiObject -Class Win32_PhysicalMemory -Property Speed | Select-Object -ExpandProperty Speed | Sort-Object | Select-Object -Unique -First 1) -And (Get-WmiObject -Class Win32_PhysicalMemory -Property ConfiguredClockSpeed -ErrorAction Ignore -WarningAction Ignore | Select-Object -ExpandProperty ConfiguredClockSpeed | Sort-Object | Select-Object -Unique -First 1)){" [$(Get-WmiObject -Class Win32_PhysicalMemory -Property ConfiguredClockSpeed | Select-Object -ExpandProperty ConfiguredClockSpeed | Sort-Object | Select-Object -Unique -First 1)/$(Get-WmiObject -Class Win32_PhysicalMemory -Property Speed | Select-Object -ExpandProperty Speed | Sort-Object | Select-Object -Unique -First 1) MT/s]"} ElseIf ((Get-WmiObject -Class Win32_PhysicalMemory -Property Speed | Select-Object -ExpandProperty Speed | Sort-Object | Select-Object -Unique -First 1)){" [$(Get-WmiObject -Class Win32_PhysicalMemory -Property Speed | Select-Object -ExpandProperty Speed | Sort-Object | Select-Object -Unique -First 1) MT/s]"})" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Gray -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
Write-Host
# End line 9

# Start line 10
'           ###    ###                   ' -Split '' | % {Write-Host -NoNewLine -Object $_ -ForeGroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}; 
"Graphics:      " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
If ($GPUs.Count)
{
    For ($I = 0; $I -Lt $GPUs.Count; $I++)
    {
        If ($I -Eq $GPUs.Count-1){$Append=""}Else{$Append="; "}
        If ($GPUs[$I].Vendor -Match '^AMD' -Or $GPUs[$I].Vendor -Match '^ATI')
        {
            "$($GPUs[$I].Model)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
            "$($Append)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
        ElseIf ($GPUs[$I].Vendor -Match 'Intel')
        {
            "$($GPUs[$I].Model)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Blue; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
            "$($Append)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
        ElseIf ($GPUs[$I].Vendor -Match 'Nvidia')
        {
            "$($GPUs[$I].Model) $(If (Get-GPUDriverVersion){"[$(Get-GPUDriverVersion)]"})"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Green; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
            "$($Append)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
        Else
        {
            "$($GPUs[$I].Model)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
            "$($Append)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        } # If
    } # For
}
ElseIf ($GPUs)
{
    If ($GPUs.Vendor -Match 'AMD' -Or $GPUs[$I].Vendor -Match 'ATI')
    {
        "$($GPUs.Model)" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
    }
    ElseIf ($GPUs.Vendor -Match 'Intel')
    {
        "$($GPUs.Model)" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Blue; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
    }
    ElseIf ($GPUs.Vendor -Match 'Nvidia')
    {
        "$($GPUs.Model) $(If (Get-GPUDriverVersion){"[$(Get-GPUDriverVersion)]"})`n" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Green; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
    }
    Else
    {
        "$($GPUs.Model)" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
    } # If
}
Else
{
    Write-Host -Object "" -NoNewLine
} # If
Write-Host
# End line 10

# Start line 11
'     ###                                ' -Split '' | % {Write-Host -NoNewLine -Object $_ -ForeGroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}; 
"Soundcard(s):  " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
If ($SoundDevs.Count)
{
    For ($I = 0; $I -Lt $SoundDevs.Count; $I++)
    {
        If ($I -Eq $SoundDevs.Count-1 -Or $I -Eq $SoundDevs.Count){$Append=""}Else{$Append="; "}
        If ($SoundDevs[$I].Manufacturer -Match 'Generic')
        {
            "$($SoundDevs[$I].ProductName)" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
            "$($Append)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
        ElseIf ($SoundDevs[$I].Manufacturer -Match '^AMD' -Or $SoundDevs[$I].Manufacturer -Match '^ATI')
        {
            "$($SoundDevs[$I].ProductName)" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
            "$($Append)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
        ElseIf ($SoundDevs[$I].Manufacturer -Match '^AVerMedia')
        {
            "$($SoundDevs[$I].ProductName)" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
            "$($Append)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
        ElseIf ($SoundDevs[$I].Manufacturer -Match '^Asus')
        {
            "$($SoundDevs[$I].ProductName)" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor DarkGray; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
            "$($Append)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
        ElseIf ($SoundDevs[$I].Manufacturer -Match '^Creative')
        {
            "$($SoundDevs[$I].ProductName)" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Gray; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
            "$($Append)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
        ElseIf ($SoundDevs[$I].Manufacturer -Match '^C\-MEDIA\sInc')
        {
            "$($SoundDevs[$I].ProductName)" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor DarkBlue; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
            "$($Append)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
        ElseIf ($SoundDevs[$I].Manufacturer -Match '^Nvidia')
        {
            "$($SoundDevs[$I].ProductName)" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Green; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
            "$($Append)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
        ElseIf ($SoundDevs[$I].Manufacturer -Match '^Intel')
        {
            "$($SoundDevs[$I].ProductName)" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Blue; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
            "$($Append)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
        ElseIf ($SoundDevs[$I].Manufacturer -Match '^Realtek')
        {
            "$($SoundDevs[$I].ProductName)" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Blue; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
            "$($Append)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
        Else
        {
            "$($SoundDevs[$I].ProductName)" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
            "$($Append)"  -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        } # If
    } # For
}
Else
{
    Write-Host -Object "" -NoNewLine
} # If
Write-Host
# End line 11

# Start line 12
'############        ######              ' -Split '' | % {Write-Host -NoNewLine -Object $_ -ForeGroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}; 
"IPv4 Address:  " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
#"$((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Ignore -WarningAction Ignore | Where-Object -FilterScript {$_.InterfaceAlias -NotLike "Loopback*"} | Where-Object -FilterScript {$_.IPAddress -NotLike "169.254.*"} | Select-Object -Property @{Name='Interface'; Expression={"$($_.InterfaceAlias): $($_.IPAddress)"}} | Select-Object -ExpandProperty Interface) -Join '; ')`n" 
$IPv4String -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Yellow -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
Write-Host
# End line 12

# Start line 13
'    &###                                ' -Split '' | % {Write-Host -NoNewLine -Object $_ -ForeGroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}; 
"Volumes:       " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$((Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object -Property @{Name="Drive"; Expression={"$($_.DeviceID)($(Size-ToString ($_.Size-$_.FreeSpace))/$(Size-ToString ($_.Size)))"}} | Select-Object -ExpandProperty Drive) -Join '; ')" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Magenta -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
Write-Host
# End line 13

# Start line 14
'           ###    ###                   ' -Split '' | % {Write-Host -NoNewLine -Object $_ -ForeGroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}; 
"DiskDrive(s):  " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$((Get-WmiObject -Class Win32_DiskDrive -Property Model | Select-Object -ExpandProperty Model) -Join '; ')" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Magenta; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
Write-Host
# End line 14

# Start line 15
'          ####     ##                   ' -Split '' | % {Write-Host -NoNewLine -Object $_ -ForeGroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}; 
"DateTime:      " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$(Get-Date -UFormat "%Y/%m/%d %r %Z")" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor DarkYellow -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
Write-Host
# End line 15

Write-Host "`n"
$GitPath = Get-Item -Path "C:\Program *" | Get-ChildItem -Filter "git.exe" -Recurse -File -ErrorAction Ignore -WarningAction Ignore | Select-Object -ExpandProperty FullName
Function Prompt
{

    #$Host.UI.RawUI.WindowTitle = "$(If ($RunningAsAdministrator){"Administrator: "})PwSh: $(If ((Get-History -ErrorAction Ignore -WarningAction Ignore).Count -Gt 0){(Get-History)[-1].CommandLine})"

    If ($GitPath -And (git rev-parse --is-inside-work-tree))
    {

        If ($GitBranch) { Clear-Variable -Name GitBranch }
        $GitBranch = ((git branch -l)  -Split '\n' -Match '^\*').Replace('* ','')
        $GitRepo = (git rev-parse --show-toplevel).Split('/')
        $GitRepo = [System.String] $GitRepo[$GitRepo.Count-1]

    }
    Else
    {

        Clear-Variable -Name GitBranch -Force -WarningAction Ignore -ErrorAction Ignore
        Clear-Variable -Name GitRepo -Force -WarningAction Ignore -ErrorAction Ignore

    }

    Write-Host -Object "PS" -NoNewLine -ForegroundColor Yellow
    Write-Host -Object ":Cmd:" -NoNewline -ForegroundColor White
    Write-Host -Object "$(If(Get-History){Get-History | Select-Object -Last 1 -ExpandProperty Id}Else{0}) " -NoNewline -ForegroundColor Cyan
    If ($GitBranch -And $GitRepo)
    {
        Write-Host -Object " $($GitRepo) " -NoNewLine -ForegroundColor Black -BackgroundColor Yellow
        Write-Host -Object " $($GitBranch) " -NoNewLine -ForegroundColor White -BackgroundColor Red
        Write-Host -Object " " -NoNewLine
        Write-Host -Object "[" -NoNewLine -ForegroundColor White
        Write-Host -Object "$($env:USERDOMAIN)" -NoNewLine -ForegroundColor Red
        Write-Host -Object "\" -NoNewLine -ForegroundColor White
        Write-Host -Object "$($env:USERNAME)" -NoNewLine -ForegroundColor DarkYellow
        Write-Host -Object "] " -NoNewLine -ForegroundColor White
        Write-Host -Object "(" -NoNewLine -ForegroundColor White
        Write-Host -Object "$(Get-Date -UFormat "%Y/%m/%d %r")" -NoNewLine -ForegroundColor Cyan
        Write-Host -Object ") " -NoNewLine -ForegroundColor White
    }
    ElseIf (-Not ($env:USERDNSDOMAIN))
    {
        Write-Host -Object "[" -NoNewLine -ForegroundColor White
        Write-Host -Object "$($env:USERDOMAIN)" -NoNewLine -ForegroundColor Red
        Write-Host -Object "\" -NoNewLine -ForegroundColor White
        Write-Host -Object "$($env:USERNAME)" -NoNewLine -ForegroundColor DarkYellow
        Write-Host -Object "] " -NoNewLine -ForegroundColor White
        Write-Host -Object "(" -NoNewLine -ForegroundColor White
        Write-Host -Object "$(Get-Date -UFormat "%Y/%m/%d %r")" -NoNewLine -ForegroundColor Cyan
        Write-Host -Object ") " -NoNewLine -ForegroundColor White
    }
    Else
    {
        Write-Host -Object "[" -NoNewLine -ForegroundColor White
        Write-Host -Object "$($env:USERNAME)" -NoNewLine -ForegroundColor Red
        Write-Host -Object '@' -NoNewLine -ForegroundColor White
        Write-Host -Object "$($env:USERDNSDOMAIN)" -NoNewLine -ForegroundColor DarkYellow
        Write-Host -Object "] " -NoNewLine -ForegroundColor White
        Write-Host -Object "(" -NoNewLine -ForegroundColor White
        Write-Host -Object "$(Get-Date -UFormat "%Y/%m/%d %r")" -NoNewLine -ForegroundColor Cyan
        Write-Host -Object ") " -NoNewLine -ForegroundColor White
    } # If
    Write-Host -Object "$((Get-Location | Select-Object -ExpandProperty Path).Replace('Microsoft.PowerShell.Core\FileSystem::', ''))" -NoNewLine -ForeGroundColor White
    If ($CurPath) {Clear-Variable -Name CurPath}
    Return "> "

} # Function