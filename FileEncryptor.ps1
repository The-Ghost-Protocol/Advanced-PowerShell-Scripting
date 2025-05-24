Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Security

# Convert plain text password to SecureString
function ConvertTo-SecureStringFromPlainText {
    param (
        [Parameter(Mandatory)]
        [string]$PlainText
    )
    $secureString = New-Object System.Security.SecureString
    $PlainText.ToCharArray() | ForEach-Object { $secureString.AppendChar($_) }
    $secureString.MakeReadOnly()
    return $secureString
}

# Derive AES key and IV from password and salt using PBKDF2
function Get-AesKeyIv {
    param (
        [Parameter(Mandatory)]
        [System.Security.SecureString]$Password,
        [Parameter(Mandatory)]
        [byte[]]$Salt
    )
    # Convert SecureString to BSTR then to byte[] of UTF8
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    try {
        $passwordString = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        $passwordBytes = [Text.Encoding]::UTF8.GetBytes($passwordString)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }

    $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($passwordBytes, $Salt, 10000)
    $key = $deriveBytes.GetBytes(32)  # 256-bit key
    $iv = $deriveBytes.GetBytes(16)   # 128-bit IV
    return @{ Key = $key; IV = $iv }
}

function Protect-File {
    param(
        [string]$InputFile,
        [string]$OutputFile,
        [byte[]]$Key,
        [byte[]]$IV
    )

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $Key
    $aes.IV = $IV

    $encryptor = $aes.CreateEncryptor()

    $inputStream = [System.IO.File]::OpenRead($InputFile)
    $outputStream = [System.IO.File]::Open($OutputFile, [System.IO.FileMode]::Create)

    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($outputStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $buffer = New-Object byte[] 1048576  # 1 MB buffer
    while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $cryptoStream.Write($buffer, 0, $read)
    }

    $cryptoStream.FlushFinalBlock()

    $cryptoStream.Close()
    $inputStream.Close()
    $outputStream.Close()
}

function Unprotect-File {
    param(
        [string]$InputFile,
        [string]$OutputFile,
        [byte[]]$Key,
        [byte[]]$IV
    )

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $Key
    $aes.IV = $IV

    $decryptor = $aes.CreateDecryptor()

    $inputStream = [System.IO.File]::OpenRead($InputFile)
    $outputStream = [System.IO.File]::Open($OutputFile, [System.IO.FileMode]::Create)

    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($inputStream, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
    $buffer = New-Object byte[] 1048576  # 1 MB buffer
    while (($read = $cryptoStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $outputStream.Write($buffer, 0, $read)
    }

    $cryptoStream.Close()
    $inputStream.Close()
    $outputStream.Close()
}

function Write-Status {
    param(
        [string]$Message
    )
    $txtStatus.AppendText($Message + "`r`n")
    $txtStatus.SelectionStart = $txtStatus.Text.Length
    $txtStatus.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

function Start-FileProcessing {
    param(
        [string]$SourceFolder,
        [string]$DestFolder,
        [byte[]]$Key,
        [byte[]]$IV,
        [ValidateSet("Encrypt", "Decrypt")]
        [string]$Mode
    )

    $files = Get-ChildItem -Path $SourceFolder -Recurse -File -ErrorAction SilentlyContinue
    $count = $files.Count
    $index = 0

    foreach ($file in $files) {
        $index++
        $relativePath = $file.FullName.Substring($SourceFolder.Length).TrimStart('\')
        $destPath = Join-Path $DestFolder $relativePath
        $destDir = Split-Path $destPath

        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }

        if ($Mode -eq "Encrypt") {
            $destPath += ".aes"
            Write-Status "[$index/$count] Encrypting $($file.FullName) ..."
            try {
                Protect-File -InputFile $file.FullName -OutputFile $destPath -Key $Key -IV $IV
            }
            catch {
                Write-Status "Error encrypting $($file.FullName): $_"
            }
        }
        else {
            # Expecting .aes extension
            if ($file.Extension -ne ".aes") {
                Write-Status "Skipping non-.aes file: $($file.FullName)"
                continue
            }
            $destPath = $destPath.Substring(0, $destPath.Length - 4) # Remove .aes extension
            Write-Status "[$index/$count] Decrypting $($file.FullName) ..."
            try {
                Unprotect-File -InputFile $file.FullName -OutputFile $destPath -Key $Key -IV $IV
            }
            catch {
                Write-Status "Error decrypting $($file.FullName): $_"
            }
        }
    }
}

# === UI Setup ===

$form = New-Object System.Windows.Forms.Form
$form.Text = "File Encryptor/Decryptor"
$form.Size = New-Object System.Drawing.Size(600,400)
$form.StartPosition = "CenterScreen"

# Source folder picker
$lblSource = New-Object System.Windows.Forms.Label
$lblSource.Location = New-Object System.Drawing.Point(10,20)
$lblSource.Size = New-Object System.Drawing.Size(100,20)
$lblSource.Text = "Source Folder:"
$form.Controls.Add($lblSource)

$txtSource = New-Object System.Windows.Forms.TextBox
$txtSource.Location = New-Object System.Drawing.Point(110,18)
$txtSource.Size = New-Object System.Drawing.Size(380,20)
$form.Controls.Add($txtSource)

$btnBrowseSource = New-Object System.Windows.Forms.Button
$btnBrowseSource.Location = New-Object System.Drawing.Point(500,16)
$btnBrowseSource.Size = New-Object System.Drawing.Size(75,23)
$btnBrowseSource.Text = "Browse"
$form.Controls.Add($btnBrowseSource)

$btnBrowseSource.Add_Click({
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($folderBrowser.ShowDialog() -eq "OK") {
        $txtSource.Text = $folderBrowser.SelectedPath
    }
})

# Destination folder picker
$lblDest = New-Object System.Windows.Forms.Label
$lblDest.Location = New-Object System.Drawing.Point(10,60)
$lblDest.Size = New-Object System.Drawing.Size(100,20)
$lblDest.Text = "Destination Folder:"
$form.Controls.Add($lblDest)

$txtDest = New-Object System.Windows.Forms.TextBox
$txtDest.Location = New-Object System.Drawing.Point(110,58)
$txtDest.Size = New-Object System.Drawing.Size(380,20)
$form.Controls.Add($txtDest)

$btnBrowseDest = New-Object System.Windows.Forms.Button
$btnBrowseDest.Location = New-Object System.Drawing.Point(500,56)
$btnBrowseDest.Size = New-Object System.Drawing.Size(75,23)
$btnBrowseDest.Text = "Browse"
$form.Controls.Add($btnBrowseDest)

$btnBrowseDest.Add_Click({
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($folderBrowser.ShowDialog() -eq "OK") {
        $txtDest.Text = $folderBrowser.SelectedPath
    }
})

# Password input
$lblPass = New-Object System.Windows.Forms.Label
$lblPass.Location = New-Object System.Drawing.Point(10,100)
$lblPass.Size = New-Object System.Drawing.Size(100,20)
$lblPass.Text = "Password:"
$form.Controls.Add($lblPass)

$txtPass = New-Object System.Windows.Forms.TextBox
$txtPass.Location = New-Object System.Drawing.Point(110,98)
$txtPass.Size = New-Object System.Drawing.Size(380,20)
$txtPass.UseSystemPasswordChar = $true
$form.Controls.Add($txtPass)

# Buttons
$btnEncrypt = New-Object System.Windows.Forms.Button
$btnEncrypt.Location = New-Object System.Drawing.Point(110,140)
$btnEncrypt.Size = New-Object System.Drawing.Size(75,30)
$btnEncrypt.Text = "Encrypt"
$form.Controls.Add($btnEncrypt)

$btnDecrypt = New-Object System.Windows.Forms.Button
$btnDecrypt.Location = New-Object System.Drawing.Point(210,140)
$btnDecrypt.Size = New-Object System.Drawing.Size(75,30)
$btnDecrypt.Text = "Decrypt"
$form.Controls.Add($btnDecrypt)

# Status textbox (multiline)
$txtStatus = New-Object System.Windows.Forms.TextBox
$txtStatus.Location = New-Object System.Drawing.Point(10,190)
$txtStatus.Size = New-Object System.Drawing.Size(560,160)
$txtStatus.Multiline = $true
$txtStatus.ScrollBars = "Vertical"
$txtStatus.ReadOnly = $true
$form.Controls.Add($txtStatus)

# Set default destination folder to C:\ on form load
$form.Add_Shown({
    $txtDest.Text = "C:\"
})

# Encrypt button click
$btnEncrypt.Add_Click({
    if ([string]::IsNullOrWhiteSpace($txtSource.Text) -or -not (Test-Path $txtSource.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a valid Source Folder.","Error","OK","Error")
        return
    }
    if ([string]::IsNullOrWhiteSpace($txtDest.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a Destination Folder.","Error","OK","Error")
        return
    }
    if ([string]::IsNullOrWhiteSpace($txtPass.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a Password.","Error","OK","Error")
        return
    }

    $form.Enabled = $false
    Write-Status "Starting encryption..."
    $txtStatus.Clear()

    # Generate random salt
    $salt = New-Object byte[] 16
    (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($salt)
    $saltFile = Join-Path $txtDest.Text "salt.bin"
    [System.IO.File]::WriteAllBytes($saltFile, $salt)

    $securePass = ConvertTo-SecureStringFromPlainText $txtPass.Text
    $keyIv = Get-AesKeyIv -Password $securePass -Salt $salt

    try {
        Start-FileProcessing -SourceFolder $txtSource.Text -DestFolder $txtDest.Text -Key $keyIv.Key -IV $keyIv.IV -Mode Encrypt
        Write-Status "Encryption completed successfully."
        Write-Status "Salt saved to salt.bin in destination folder."

        # Update source textbox to destination folder for decryption
        $txtSource.Text = $txtDest.Text
    }
    catch {
        Write-Status "Encryption failed: $_"
    }
    finally {
        $form.Enabled = $true
    }
})

# Decrypt button click
$btnDecrypt.Add_Click({
    if ([string]::IsNullOrWhiteSpace($txtSource.Text) -or -not (Test-Path $txtSource.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a valid Source Folder.","Error","OK","Error")
        return
    }
    if ([string]::IsNullOrWhiteSpace($txtDest.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a Destination Folder.","Error","OK","Error")
        return
    }
    if ([string]::IsNullOrWhiteSpace($txtPass.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a Password.","Error","OK","Error")
        return
    }

    $form.Enabled = $false
    Write-Status "Starting decryption..."
    $txtStatus.Clear()

    # Load salt from salt.bin in source folder
    $saltFile = Join-Path $txtSource.Text "salt.bin"
    if (-not (Test-Path $saltFile)) {
        [System.Windows.Forms.MessageBox]::Show("Salt file (salt.bin) not found in source folder.","Error","OK","Error")
        $form.Enabled = $true
        return
    }
    $salt = [System.IO.File]::ReadAllBytes($saltFile)

    $securePass = ConvertTo-SecureStringFromPlainText $txtPass.Text
    $keyIv = Get-AesKeyIv -Password $securePass -Salt $salt

    try {
        Start-FileProcessing -SourceFolder $txtSource.Text -DestFolder $txtDest.Text -Key $keyIv.Key -IV $keyIv.IV -Mode Decrypt
        Write-Status "Decryption completed successfully."
    }
    catch {
        Write-Status "Decryption failed: $_"
    }
    finally {
        $form.Enabled = $true
    }
})

[void] $form.ShowDialog()
