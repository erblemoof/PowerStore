###############################################################################
# Windows AppX Installer Spoofing Vulnerability
# First two variables define the name and New Version # of the MS Store app

$StoApp = "Microsoft.DesktopAppInstaller"
$NewVer = "1.16.13405.0"

# Next two lines are there so you can just select them, along with the variables
# above and press F8 in PowerShell_ISE to run them and see what's installed.
Get-AppxPackage -AllUsers -Name $StoApp
Get-AppxProvisionedPackage -Online | Where {$_.DisplayName -EQ $StoApp}

# Check for whether the latest ($Update) and/or older ($OldVer) are installed
$Update = Get-AppxPackage -AllUsers -Name $StoApp | Where-Object Version -EQ $NewVer
$OldVer = Get-AppxPackage -AllUsers -Name $StoApp | Where-Object Version -LT $NewVer

# If the update is installed and no older versions, exit with True
If ($Update -And -Not $OldVer) {Return $true} Else {Return $false}

######
# Uninstall old version(s) of Provisioned Microsoft Store Application
# Repeat variables from before, or remove the world "Return" in Else {Return $false}
$StoApp = "Microsoft.DesktopAppInstaller"
$NewVer = "1.16.13405.0"
$Ver = Get-AppxPackage -AllUsers -PackageTypeFilter All -Name Microsoft.DesktopAppInstaller | Where-Object Version -EQ $NewVer

# Always first try to remove the app as if it's a provisioned app (whether it is or not)
# because if a removal attempt is first made on a provisioned app using Remove-AppxPackage, it messes up SysPrep
If ($Ver) {
           Get-AppxProvisionedPackage -Online | Where {$_.DisplayName -EQ $StoApp -And $_.Version -LT $NewVer} | Remove-AppxProvisionedPackage -Online
           Get-AppxPackage -AllUsers -Name $StoApp | Where-Object Version -LT $NewVer | Remove-AppxPackage -AllUsers
          }

# Flip registry data to trigger Qualys scan
$registryPath = "HKLM:\SOFTWARE\Qualys\QualysAgent\ScanOnDemand\Vulnerability"
$Name = "ScanOnDemand"
$value = "1"
IF(!(Test-Path $registryPath))
  {
      New-Item -Path $registryPath -Force | Out-Null
      New-ItemProperty -Path $registryPath -Name $name -Value $value `
      -PropertyType DWORD -Force | Out-Null}
 ELSE {
      New-ItemProperty -Path $registryPath -Name $name -Value $value `
      -PropertyType DWORD -Force | Out-Null}
