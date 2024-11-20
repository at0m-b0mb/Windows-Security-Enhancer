function Enforce-UACPasswordPrompt {
    Write-Host "Enforcing UAC to require a password for admin tasks..."

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    if (-not (Test-Path -Path $regPath)) {
        Write-Host "Registry path does not exist. Creating path..."
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "System" -Force
    }

    if (-not (Test-Path "$regPath\ConsentPromptBehaviorAdmin")) {
        Write-Host "Registry value 'ConsentPromptBehaviorAdmin' does not exist. Creating..."
        New-ItemProperty -Path $regPath -Name "ConsentPromptBehaviorAdmin" -Value 1 -PropertyType DWord -Force
    }

    if (-not (Test-Path "$regPath\PromptOnSecureDesktop")) {
        Write-Host "Registry value 'PromptOnSecureDesktop' does not exist. Creating..."
        New-ItemProperty -Path $regPath -Name "PromptOnSecureDesktop" -Value 1 -PropertyType DWord -Force
    }

    Set-ItemProperty -Path $regPath -Name "ConsentPromptBehaviorAdmin" -Value 1
    Set-ItemProperty -Path $regPath -Name "PromptOnSecureDesktop" -Value 1

    Write-Host "UAC has been configured to require a password for admin tasks."
}

function Disable-UACPasswordPrompt {
    Write-Host "Restoring UAC to default (Normal) settings..."

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    # Revert ConsentPromptBehaviorAdmin and PromptOnSecureDesktop to normal UAC settings (default values)
    Set-ItemProperty -Path $regPath -Name "ConsentPromptBehaviorAdmin" -Value 5
    Set-ItemProperty -Path $regPath -Name "PromptOnSecureDesktop" -Value 0

    Write-Host "UAC has been restored to default settings."
}

function Set-AccountLockoutPolicy {
    Write-Host "Setting account lockout policy..."

    # Setting the account lockout policy
    net accounts /lockoutthreshold:3 /lockoutduration:15 /lockoutwindow:15
    Write-Host "Account lockout policy has been configured."
}

function Disable-AccountLockoutPolicy {
    Write-Host "Restoring account lockout policy to default settings..."

    # Restoring the default lockout policy (no lockout threshold)
    net accounts /lockoutthreshold:0
    Write-Host "Account lockout policy has been restored to default settings."
}

function Disable-Cameras {
    Write-Host "Detecting and disabling connected camera devices..."
    $cameras = Get-WmiObject -Query "SELECT * FROM Win32_PnPEntity WHERE Description LIKE '%camera%'"
    
    if ($cameras.Count -eq 0) {
        Write-Host "No camera devices found."
    } else {
        foreach ($camera in $cameras) {
            $deviceId = $camera.DeviceID
            Write-Host "Disabling device: $($camera.Description)"
            Disable-PnpDevice -InstanceId $deviceId -Confirm:$false
        }
        Write-Host "All connected camera devices have been disabled."
    }
}

function Enable-Cameras {
    Write-Host "Enabling connected camera devices..."
    $cameras = Get-WmiObject -Query "SELECT * FROM Win32_PnPEntity WHERE Description LIKE '%camera%'"
    
    if ($cameras.Count -eq 0) {
        Write-Host "No camera devices found."
    } else {
        foreach ($camera in $cameras) {
            $deviceId = $camera.DeviceID
            Write-Host "Enabling device: $($camera.Description)"
            Enable-PnpDevice -InstanceId $deviceId -Confirm:$false
        }
        Write-Host "All connected camera devices have been enabled."
    }
}

function Set-UACAlwaysNotify {
    Write-Host "Setting UAC to 'Always Notify'..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1
    Write-Host "UAC has been set to 'Always Notify'."
}

function Restore-UACToNormal {
    Write-Host "Restoring UAC to default settings..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 0
    Write-Host "UAC has been restored to default settings."
}



# Function to disable USB ports
function Disable-USBPorts {
    Write-Host "Disabling USB Ports..."

    # Get all USB Root Hub devices
    $usbRootHubs = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.DeviceID -match "ROOT_HUB" }

    foreach ($hub in $usbRootHubs) {
        try {
            # Attempt to disable the USB hub
            $hub.PSBase.InvokeMethod('Disable', $null)
            Write-Host "Disabled: $($hub.DeviceID)"
        } catch {
            Write-Host "Error disabling device: $($hub.DeviceID)"
            # Log errors to a file for later troubleshooting
            $errorMessage = "Failed to disable device: $($hub.DeviceID) - Error: $($_.Exception.Message)"
            Add-Content "C:\usb_disable_errors.log" -Value $errorMessage
        }
    }
}

# Function to enable USB ports
function Enable-USBPorts {
    Write-Host "Enabling USB Ports..."

    # Get all USB Root Hub devices
    $usbRootHubs = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.DeviceID -match "ROOT_HUB" }

    foreach ($hub in $usbRootHubs) {
        try {
            # Attempt to enable the USB hub
            $hub.PSBase.InvokeMethod('Enable', $null)
            Write-Host "Enabled: $($hub.DeviceID)"
        } catch {
            Write-Host "Error enabling device: $($hub.DeviceID)"
            # Log errors to a file for later troubleshooting
            $errorMessage = "Failed to enable device: $($hub.DeviceID) - Error: $($_.Exception.Message)"
            Add-Content "C:\usb_enable_errors.log" -Value $errorMessage
        }
    }
}

function Show-Menu {
    Write-Host "Choose an option:"
    Write-Host "1. Enforce UAC to require a password"
    Write-Host "2. Disable UAC password requirement"
    Write-Host "3. Set account lockout policy"
    Write-Host "4. Restore account lockout policy to default"
    Write-Host "5. Detect and disable connected cameras"
    Write-Host "6. Enable connected cameras"
    Write-Host "7. Set UAC to 'Always Notify'"
    Write-Host "8. Restore UAC to default settings"
    Write-Host "9. Disable USB ports"
    Write-Host "10. Enable USB ports"
    Write-Host "11. Run all tasks"
    Write-Host "12. Exit"
    $choice = Read-Host "Enter your choice (1-12)"
    return $choice
}

do {
    $userChoice = Show-Menu

    switch ($userChoice) {
        1 { Enforce-UACPasswordPrompt }
        2 { Disable-UACPasswordPrompt }
        3 { Set-AccountLockoutPolicy }
        4 { Disable-AccountLockoutPolicy }
        5 { Disable-Cameras }
        6 { Enable-Cameras }
        7 { Set-UACAlwaysNotify }
        8 { Restore-UACToNormal }
        9 { Disable-USBPorts }
        10 { Enable-USBPorts }
        11 { 
            Enforce-UACPasswordPrompt
            Set-AccountLockoutPolicy
            Disable-Cameras
            Set-UACAlwaysNotify
            Disable-USBPorts
        }
        12 { Write-Host "Exiting the script..."; break }
        default { Write-Host "Invalid choice. Please select a valid option (1-12)." }
    }
} while ($userChoice -ne 12)
