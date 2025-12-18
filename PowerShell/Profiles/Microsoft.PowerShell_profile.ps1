If (-Not (Get-Command -Name 'Get-NetIPAddress' -ErrorAction Ignore -WarningAction Ignore))
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
        )

        Begin
        {
            $AddressLines = $(netsh.exe interface ipv4 show addresses) -Replace '\s{2,}', '' -Split '\n' | Where-Object {-Not [System.String]::IsNullOrEmpty($_)}
            $Addresses = [System.Collections.ArrayList]::New()
        }

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
                        [Void] $Addresses.Add([PSCustomObject]@{InterfaceAlias = "$InterfaceAlias"; DHCPEnabled = $DHCPEnabled; IPAddress = $IPAddress})
                    }
                }
            }
        }

        End
        {
            Return $Addresses
        }
    }

}

Function Get-GPUDriverVersion
{
    Begin
    {
        $QuickSearch = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe", "C:\Program Files (x86)\NVIDIA Corporation\NVSMI\nvidia-smi.exe", "C:\Windows\System32\nvidia-smi.exe", "C:\Windows\System32\DriverStore\FileRepository\nvhd.inf*\nvidia-smi.exe"
        $NVSMI = $QuickSearch | Where-Object {(Test-Path -Path $_) -Eq "$True"} | Select-Object -First 1 -Unique | Get-Item | Select-Object -ExpandProperty FullName
    }

    Process
    {
        #
    }

    End
    {
        If (-Not $NVSMI){$NVSMI = Get-ChildItem -Path "$($env:SystemDrive)\" -Directory | Where-Object -FilterScript {$_.Name -Like "Program Files*" -Or $_.Name -Eq 'Windows'} | Get-ChildItem -Recurse -Filter "nvidia-smi.exe" | Select-Object -ExpandProperty FullName -First 1}
        $DrvV = (. $NVSMI --query-gpu=driver_version --format=csv |findstr /i /v "driver_version") -Replace "\s","" |sort | select -f 1
        Return $DrvV
    }
}

Function Get-FQDNHostName ()
{

	$Domain = Get-WmiObject -Class Win32_ComputerSystem -Property Domain | Select-Object -ExpandProperty Domain
	$HostName = Get-WmiObject -Class Win32_ComputerSystem -Property Name | Select-Object -ExpandProperty Name

	Return "$($HostName).$($Domain)"

}

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

Function Set-WallPaper {
 
<#
 
    .SYNOPSIS
    Applies a specified wallpaper to the current user's desktop
    
    .PARAMETER Image
    Provide the exact path to the image
 
    .PARAMETER Style
    Provide wallpaper style (Example: Fill, Fit, Stretch, Tile, Center, or Span)
  
    .EXAMPLE
    Set-WallPaper -Image "C:\Wallpaper\Default.jpg"
    Set-WallPaper -Image "C:\Wallpaper\Background.jpg" -Style Fit
  
#>
 
Param 
(
    [Parameter(
        Mandatory=$True
    )]
    # Provide path to image
    [System.String] $Image,
    # Provide wallpaper style that you would like applied
    [Parameter(
        Mandatory=$False
    )]
    [ValidateSet(
        'Fill',
        'Fit',
        'Stretch',
        'Tile',
        'Center',
        'Span'
    )]
    [System.String] $Style
)
 
$WallpaperStyle = Switch ($Style) {
  
    "Fill" {"10"}
    "Fit" {"6"}
    "Stretch" {"2"}
    "Tile" {"0"}
    "Center" {"0"}
    "Span" {"22"}
  
}
 
If ($Style -eq "Tile")
{
 
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value $WallpaperStyle -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 1 -Force
 
}
Else 
{
 
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value $WallpaperStyle -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 0 -Force
 
}
 
Add-Type -TypeDefinition @" 
using System; 
using System.Runtime.InteropServices;
  
public class Params
{ 
    [DllImport("User32.dll",CharSet=CharSet.Unicode)] 
    public static extern int SystemParametersInfo (Int32 uAction, 
                                                   Int32 uParam, 
                                                   String lpvParam, 
                                                   Int32 fuWinIni);
}
"@ 
  
    $SPI_SETDESKWALLPAPER = 0x0014
    $UpdateIniFile = 0x01
    $SendChangeEvent = 0x02
  
    $fWinIni = $UpdateIniFile -bor $SendChangeEvent
  
    $ret = [Params]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $Image, $fWinIni)
}

Function Set-LockScreenImage
{

<#
 
    .SYNOPSIS
    Applies a specified image to the lockscreen
    
    .PARAMETER Path
    Provide the exact path to the image
  
    .EXAMPLE
    Set-LockScreenImage -Path "C:\Windows\Web\Screen\img100.jpg"
    Set-LockScreenImage -Path "C:\Wallpaper\Background.jpg"
  
#>

    Param
    (
        [Parameter(
            Mandatory = $True,
            Position = 0,
            HelpMessage = "Full Path to lock screen image.",
            ValueFromPipeline = $True
        )]
        [System.String] $Path
    )

    Begin
    {
        
        $RegKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
        If (!(Test-Path -Path $RegKey))
        {
            
            $Null = New-Item -Path $regKey

        }

    }

    Process
    {
        
        Set-ItemProperty -Path $RegKey -Name LockScreenImage -Value $Path

    }

    End
    {
        
        Return ("$Path" | Get-Item)

    }

}

Function Get-YubikeyDriver
{
    <#
        Returns the driver(s) if there exists a Yubico SmartCard driver.
    #>
    Begin
    {

    }

    Process
    {

    }

    End
    {
        Return (Get-WindowsDriver -Online | ? {$_.ClassName -Eq "SmartCard" -And $_.ProviderName -Eq "Yubico"})
    }
}

Function Install-YubikeyDriver
{
    <#
        Installs the Yubikey minidriver if the server can access the location of the driver.
        By default it installs with INSTALL_LEGACY_NODE=1.
    #>
    Param
    (
        [Parameter(
            Mandatory = $False,
            HelpMessage = "True for LEGACY_NODE False for standard.",
            Position = 0,
            ValueFromPipeline = $True
            )
        ]
        [ValidateSet({$True,$False})]
        [Bool] $Legacy = $True    
    )

    Begin
    {

    }

    Process
    {

    }

    End
    {
        If ($Legacy)
        {
            #$Cmd = 'msiexec.exe /i \\cifs-ihelse.ihelse.net\Ikt\Dsl\YubiKey\YubiKey-Minidriver-4.1.1.210-x64.msi INSTALL_LEGACY_NODE=1 /quiet'
            Start-Process -FilePath "$($env:SystemRoot)\System32\msiexec.exe" -ArgumentList '/i','\\SCADIC.COM\Drivers\Yubikey\YubiKey-Minidriver-4.1.1.210-x64.msi','INSTALL_LEGACY_NODE=1','/quiet' -Wait
        }
        Else
        {
            #$Cmd = 'msiexec.exe /i \\cifs-ihelse.ihelse.net\Ikt\Dsl\YubiKey\YubiKey-Minidriver-4.1.1.210-x64.msi /quiet'
            Start-Process -FilePath "$($env:SystemRoot)\System32\msiexec.exe" -ArgumentList '/i','\\SCADIC.COM\Drivers\Yubikey\YubiKey-Minidriver-4.1.1.210-x64.msi','/quiet' -Wait
        }
    }
}

$GitPath = Get-Item -Path "C:\Program *" | Get-ChildItem -Filter "git.exe" -Recurse -File -ErrorAction Ignore -WarningAction Ignore | Select-Object -ExpandProperty FullName

If ($ExecutionContext.SessionState.LanguageMode -Eq "FullLanguage")
{
    $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $RunningAsAdministrator = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $PSVersion = $PSVersionTable.PSVersion

    Function Set-ConstrainedLanguageMode
    {
        Write-Verbose -Message "Current Language Mode: $($ExecutionContext.SessionState.LanguageMode)"
        $OldTitle = $Host.UI.RawUI.WindowTitle.Clone()
        $Host.UI.RawUI.WindowTitle = "[ConstrainedLanguage] $($OldTitle)"
        $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
        Write-Verbose -Message "New Language Mode: $($ExecutionContext.SessionState.LanguageMode)"
    } # Function
} # If

Function Prompt
{

    If ($ExecutionContext.SessionState.LanguageMode -Eq "FullLanguage")
    {
        $Host.UI.RawUI.WindowTitle = "$(If ($RunningAsAdministrator){"Administrator: "})PwSh v$($PSVersion.Major).$($PSVersion.Minor): $(If ((Get-History -ErrorAction Ignore -WarningAction Ignore).Count -Gt 0){(Get-History)[-1].CommandLine})"
    } # If

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
	}
	Write-Host -Object "$((Get-Location | Select-Object -ExpandProperty Path).Replace('Microsoft.PowerShell.Core\FileSystem::', ''))" -NoNewLine -ForeGroundColor White
    If ($CurPath) {Clear-Variable -Name CurPath}
	Return "> "

}

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
	Set-PSReadLineOption -PredictionViewStyle 'ListView'
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
}

Clear-Host
Start-Sleep -Milliseconds 50
$GPUs = [System.Array] (Get-WmiObject -Class Win32_VideoController -Property Name | Select-Object -ExpandProperty Name)
$GPUs = [System.Array] ($GPUs | ForEach-Object {$Split = $_ -Split '\s' ;$Obj = [PSCustomObject]@{Vendor=$($Split[0]); Model=$(($Split[(1..($Split.Count-1))] -Join ' '))}; $Obj})
Start-Sleep -Milliseconds 50
$SoundDevs = [System.Array] (Get-WmiObject -Class Win32_SoundDevice -Property Manufacturer,ProductName)
$OS = Get-CimInstance -ClassName Win32_OperatingSystem -Property LastBootUpTime | Select-Object -ExpandProperty LastBootUpTime
$UpTime = (Get-Date) - $OS
$HotFix = Get-HotFix | Sort-Object -Property InstalledOn -Descending -ErrorAction Ignore -WarningAction Ignore | Select-Object -First 1 -ExpandProperty InstalledOn | Get-Date
$IPv4String = ''
$IPv4Interfaces = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Ignore -WarningAction Ignore | Where-Object -FilterScript {$_.InterfaceAlias -NotLike "Loopback*" -And $_.AddressState -Eq "Preferred"} | Where-Object -FilterScript {$_.IPAddress -NotLike "169.254.*"})
ForEach ($IPv4Interface In $IPv4Interfaces)
{
    If ((Get-Command -Name Get-NetRoute) -And (Get-Command -Name Get-DnsClientServerAddress))
    {
        $IPv4String += "@{$($IPv4Interface.InterfaceAlias)=$($IPv4Interface.IPAddress); GW=$($($IPv4Interface | Get-NetRoute -AddressFamily IPv4 | Select-Object -ExpandProperty NextHop) -Ne '0.0.0.0' | Select-Object -Unique -First 1); DNS=@($(($IPv4Interface | Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses | ForEach-Object {"$($_)$(If (Resolve-DnsName -Name $_ -Type PTR -ErrorAction Ignore -WarningAction Ignore){"[$(Resolve-DnsName -Name $_ -Type PTR -ErrorAction Ignore -WarningAction Ignore | Select-Object -ExpandProperty NameHost -ErrorAction Ignore -WarningAction Ignore)]"})"}) -Join '; '))} "
    }
    Else
    {
        $IPv4String += "@{$($IPv4Interface.InterfaceAlias)=$($IPv4Interface.IPAddress)} "
    }
}

If ($IPv4String.Length -Gt ([System.Console]::WindowWidth - 3 - 72))
{
    $IPv4String = $IPv4String.SubString(0, ([System.Console]::WindowWidth - 3 - 72))
    $IPv4String += "..."
} # If
$OldProgressPreference = $ProgressPreference
$ProgressPreference = "SilentlyContinue"

Write-Host -Object ""
# Start 1st line
'                               &&&&&&&&&&&&&&&&&        ' -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
" Uptime:        " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$("{0:dd}d:{0:hh}h:{0:mm}m:{0:ss}s`n" -f ($UpTime))" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor White -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
# End 1st line
# Start 2nd line
'             &&&&&&&&&&&&  &&&&&&&&&&&&&&&&&&&&&        ' -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
" User:          " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$($env:USERNAME)@$(If ($env:USERDNSDOMAIN){$env:USERDNSDOMAIN}Else{$env:USERDOMAIN})`n" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Green -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
# End 2nd line
# Start 3rd line
'        %&&&&&&&&&&&&&&&&  &&&&&&&&&&&&&&&&&&&&&        ' -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
" Host:          " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$(Get-FQDNHostName)$(If ((Get-WmiObject -Class Win32_ComputerSystem -Property Model | Select-Object -ExpandProperty Model) -NotLike "System*" -And (Get-WmiObject -Class Win32_ComputerSystem -Property Model | Select-Object -ExpandProperty Model) -NotLike "All Series*"){" [Model: $(Get-WmiObject -Class Win32_ComputerSystem -Property Model | Select-Object -ExpandProperty Model)$(If ((Get-WmiObject -Class Win32_ComputerSystemProduct -Property IdentifyingNumber | Select-Object -ExpandProperty IdentifyingNumber) -NotLike "System*"){"; Serial: $(Get-WmiObject -Class Win32_ComputerSystemProduct -Property IdentifyingNumber | Select-Object -ExpandProperty IdentifyingNumber)"})]"}Else{" [Model: $(Get-WmiObject -Class Win32_BaseBoard -Property Product -ErrorAction Ignore -WarningAction Ignore | Select-Object -ExpandProperty Product)$(If ((Get-WmiObject -Class Win32_ComputerSystemProduct -Property IdentifyingNumber | Select-Object -ExpandProperty IdentifyingNumber) -NotLike "System*"){"; Serial: $(Get-WmiObject -Class Win32_ComputerSystemProduct -Property IdentifyingNumber | Select-Object -ExpandProperty IdentifyingNumber)"})]"})`n" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor DarkCyan -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
# End 3rd line
# Start 4th line
'        #&&&&&&&&&&&&&&&&  &&&&&&&&&&&&&&&&&&&&&        ' -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
" OS:            " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$((Get-WmiObject -Class Win32_OperatingSystem -Property Caption | Select-Object -ExpandProperty Caption) -Replace '^Microsoft\s', '') [$(Get-WmiObject -Class Win32_OperatingSystem -Property Version | Select-Object -ExpandProperty Version)]`n" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Cyan -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
# End 4th line
# Start 5th line
'        (&&&&&&&&&&&&&&&&  &&&&&&&&&&&&&&&&&&&&&        ' -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
" InstallDate:   " -Split '' | ForEach-Object {Write-Host -Object $_  -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$(Get-CimInstance -ClassName Win32_OperatingSystem -Property InstallDate | Select-Object -ExpandProperty InstallDate | Get-Date -UFormat '%Y/%m/%d %r %Z')`n" -Split '' | ForEach-Object {Write-Host -Object $_  -ForegroundColor Gray -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
# End 5th line
# Start 6th line
'        /&&&&&&&&&&&&&&&&  &&&&&&&&&&&&&&&&&&&&&        ' -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
" LastUpdated:   " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; ; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
If ($HotFix -Ge (Get-Date).AddMonths(-1))
{
    "$($HotFix | Get-Date -UFormat '%Y/%m/%d %r %Z')`n" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Green -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
}
ElseIf ($HotFix -Ge (Get-Date).AddMonths(-3))
{
    "$($HotFix | Get-Date -UFormat '%Y/%m/%d %r %Z')`n" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Yellow -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
}
Else
{
    "$($HotFix | Get-Date -UFormat '%Y/%m/%d %r %Z')`n" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Red -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
}
# End 6th line
# Start 7th line
'        ,&&&&&&&&&&&&&&&&  &&&&&&&&&&&&&&&&&&&&&        ' -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
" Processor(s):  " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
If ((Get-WmiObject -Class Win32_Processor -Property Name | Select-Object -ExpandProperty Name -Unique) -Match 'Intel')
{
    "$(Get-WmiObject -Class Win32_Processor -Property Name | Measure-Object | Select-Object -ExpandProperty Count)x $(Get-WmiObject -Class Win32_Processor -Property Name | Select-Object -ExpandProperty Name -Unique)`n" -Replace ' {1,}$', '' -Replace '\s{2,}', ' ' -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Blue -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
}
ElseIf ((Get-WmiObject -Class Win32_Processor -Property Name | Select-Object -ExpandProperty Name -Unique) -Match 'AMD')
{
    "$(Get-WmiObject -Class Win32_Processor -Property Name | Measure-Object | Select-Object -ExpandProperty Count)x $(Get-WmiObject -Class Win32_Processor -Property Name | Select-Object -ExpandProperty Name -Unique)`n" -Replace ' {1,}$', '' -Replace '\s{2,}', ' ' -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Red -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
}
# End 7th line
# Start 8th line
'                                                        ' -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
" Cores/Threads: " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$(Get-WmiObject -Class Win32_Processor -Property NumberOfCores | Select-Object -ExpandProperty NumberOfCores | Measure-Object -Sum | Select-Object -ExpandProperty Sum)c/$(Get-WmiObject -Class Win32_Processor -Property NumberOfLogicalProcessors | Select-Object -ExpandProperty NumberOfLogicalProcessors | Measure-Object -Sum | Select-Object -ExpandProperty Sum)t`n" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor DarkCyan -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
# End 8th line
# Start 9th line
'        *&&&&&&&&&&&&&&&&  &&&&&&&&&&&&&&&&&&&&&        ' -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
" Memory:        " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$(Size-ToString (Get-WmiObject -Class Win32_PhysicalMemory -Property * | Select-Object -Property Capacity | Measure-Object -Property Capacity -Sum | Select-Object -ExpandProperty Sum)) ($($Capacities = Get-WmiObject -Class Win32_PhysicalMemory -Property Capacity | Select-Object -ExpandProperty Capacity -Unique | Sort-Object; $Capacities | ForEach-Object {$Str = ''; $Str += Get-WmiObject -Class Win32_PhysicalMemory -Filter "Capacity=$($_)" | Measure-Object | Select-Object -ExpandProperty Count; $Str += ' x '; $Str += Size-ToString -Size ((Get-WmiObject -Class Win32_PhysicalMemory  -Filter "Capacity=$($_)" | Select-Object -ExpandProperty Capacity | Measure-Object -Sum | Select-Object -ExpandProperty Sum)/(Get-WmiObject -Class Win32_PhysicalMemory -Filter "Capacity=$($_)" | Measure-Object | Select-Object -ExpandProperty Count)); $Str}))$(If ((Get-WmiObject -Class Win32_PhysicalMemory -Property Speed | Select-Object -ExpandProperty Speed | Sort-Object | Select-Object -Unique -First 1) -And (Get-WmiObject -Class Win32_PhysicalMemory -Property ConfiguredClockSpeed -ErrorAction Ignore -WarningAction Ignore | Select-Object -ExpandProperty ConfiguredClockSpeed | Sort-Object | Select-Object -Unique -First 1)){" [$(Get-WmiObject -Class Win32_PhysicalMemory -Property ConfiguredClockSpeed | Select-Object -ExpandProperty ConfiguredClockSpeed | Sort-Object | Select-Object -Unique -First 1)/$(Get-WmiObject -Class Win32_PhysicalMemory -Property Speed | Select-Object -ExpandProperty Speed | Sort-Object | Select-Object -Unique -First 1) MT/s]"} ElseIf ((Get-WmiObject -Class Win32_PhysicalMemory -Property Speed | Select-Object -ExpandProperty Speed | Sort-Object | Select-Object -Unique -First 1)){" [$(Get-WmiObject -Class Win32_PhysicalMemory -Property Speed | Select-Object -ExpandProperty Speed | Sort-Object | Select-Object -Unique -First 1) MT/s]"})`n" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Gray -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
# End 9th line
# Start 10th line
'        *&&&&&&&&&&&&&&&&  &&&&&&&&&&&&&&&&&&&&&        ' -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
" Graphics:      " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
If ($GPUs.Count)
{
    For ($I = 0; $I -Lt $GPUs.Count; $I++)
    {
        If ($I -Eq $GPUs.Count-1){$Append="`n"}Else{$Append="; "}
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
        }
    }
}
ElseIf ($GPUs)
{
    If ($GPUs.Vendor -Match 'AMD' -Or $GPUs[$I].Vendor -Match 'ATI')
        {
            "$($GPUs.Model)`n" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Red; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
        ElseIf ($GPUs.Vendor -Match 'Intel')
        {
            "$($GPUs.Model)`n" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Blue; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
        ElseIf ($GPUs.Vendor -Match 'Nvidia')
        {
            "$($GPUs.Model) $(If (Get-GPUDriverVersion){"[$(Get-GPUDriverVersion)]"})`n" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Green; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
        Else
        {
            "$($GPUs.Model)`n" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
        }
}
Else
{
    Write-Host -Object ""
}
# End 11th line
# Start 12th line
'        *&&&&&&&&&&&&&&&&  &&&&&&&&&&&&&&&&&&&&&        ' -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
" Soundcard(s):  " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
If ($SoundDevs.Count)
{
    For ($I = 0; $I -Lt $SoundDevs.Count; $I++)
    {
        If ($I -Eq $SoundDevs.Count-1 -Or $I -Eq $SoundDevs.Count){$Append="`n"}Else{$Append="; "}
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
        }
    }
}
Else
{
    Write-Host -Object ""
}
# End 12th line
# Start 13th line
'        *&&&&&&&&&&&&&&&&  &&&&&&&&&&&&&&&&&&&&&        ' -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
" IPv4 Address:  " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
#"$((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Ignore -WarningAction Ignore | Where-Object -FilterScript {$_.InterfaceAlias -NotLike "Loopback*"} | Where-Object -FilterScript {$_.IPAddress -NotLike "169.254.*"} | Select-Object -Property @{Name='Interface'; Expression={"$($_.InterfaceAlias): $($_.IPAddress)"}} | Select-Object -ExpandProperty Interface) -Join '; ')`n" 
$IPv4String -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Yellow -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
# End 13th line
# Start 14th line
'        *&&&&&&&&&&&&&&&&  &&&&&&&&&&&&&&&&&&&&&        ' -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
" Volumes:       " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$((Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object -Property @{Name="Drive"; Expression={"$($_.DeviceID)($(Size-ToString ($_.Size-$_.FreeSpace))/$(Size-ToString ($_.Size)))"}} | Select-Object -ExpandProperty Drive) -Join '; ')`n" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor Magenta -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
# End 14th line
# Start 15th line
'              &&&&&&&&&&&  &&&&&&&&&&&&&&&&&&&&&        ' -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
" DiskDrive(s):  " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$((Get-WmiObject -Class Win32_DiskDrive -Property Model | Select-Object -ExpandProperty Model) -Join '; ')`n" -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor Magenta; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
# End 15th line
'                                &&&&&&&&&&&&&&&&        ' -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline -ForegroundColor White; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
" DateTime:      " -Split '' | ForEach-Object {Write-Host -Object $_ -NoNewline; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
"$(Get-Date -UFormat "%Y/%m/%d %r %Z")`n" -Split '' | ForEach-Object {Write-Host -Object $_ -ForegroundColor DarkYellow -NoNewLine; Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1)}
$ProgressPreference = $OldProgressPreference
#Variable Cleanup
Remove-Variable -Name Append,GPUs,HotFix,I,Obj,OS,Split,Str,SoundDevs,UpTime,IPv4String,IPv4Interfaces -ErrorAction Ignore -WarningAction Ignore