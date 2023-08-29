# git-essentials
#!/bin/ksh

# Check if LOGFILE variable is set
if [[ -z "$LOGFILE" ]]; then
    echo "LOGFILE variable is not set."
    exit 1
fi

# Check for the existence of the file
if [[ ! -e "$LOGFILE" ]]; then
    touch "$LOGFILE"
    if [[ $? -ne 0 ]]; then
        echo "Error creating $LOGFILE."
        exit 2
    fi
    chmod 666 "$LOGFILE"
    if [[ $? -ne 0 ]]; then
        echo "Error setting permissions for $LOGFILE."
        exit 3
    fi
    echo "$LOGFILE created with 666 permissions."
else
    echo "$LOGFILE already exists."
fi

exit 0

----------------------------------------------
# Define a Secure AES Key
$secureKey = 'YOUR_32_BYTE_AES_KEY_HERE' # Replace this with your 32-byte key

# Encrypt the Password
$encryptedPassword = ConvertTo-SecureString 'MySecretPassword' -AsPlainText -Force | ConvertFrom-SecureString -Key ([byte[]] [char[]] $secureKey)

# Decrypt the Password
$decryptedPassword = ConvertTo-SecureString -String $encryptedPassword -Key ([byte[]] [char[]] $secureKey) | ForEach-Object { [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($_)) }

Write-Host "Encrypted Password: $encryptedPassword"
Write-Host "Decrypted Password: $decryptedPassword"
----------------------------------------------

# Define AES Key and IV
$key = [System.Text.Encoding]::UTF8.GetBytes("YOUR_32_BYTE_AES_KEY_HERE") # Replace this with your 32-byte key
$IV = [System.Text.Encoding]::UTF8.GetBytes("YOUR_16_BYTE_IV_HERE")       # Replace this with your 16-byte IV

# Function to encrypt a string using the AES key and IV
function Encrypt-String($stringToEncrypt) {
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = $key
    $aes.IV = $IV
    $encryptor = $aes.CreateEncryptor()

    $stringBytes = [System.Text.Encoding]::UTF8.GetBytes($stringToEncrypt)
    $encryptedBytes = $encryptor.TransformFinalBlock($stringBytes, 0, $stringBytes.Length)
    return [Convert]::ToBase64String($encryptedBytes)
}

# Function to decrypt a string using the AES key and IV
function Decrypt-String($encryptedString) {
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = $key
    $aes.IV = $IV
    $decryptor = $aes.CreateDecryptor()

    $encryptedBytes = [Convert]::FromBase64String($encryptedString)
    $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
}

# Test
$plainText = "MySecretPassword"
$encryptedText = Encrypt-String -stringToEncrypt $plainText
$decryptedText = Decrypt-String -encryptedString $encryptedText

Write-Host "Original Text: $plainText"
Write-Host "Encrypted Text: $encryptedText"
Write-Host "Decrypted Text: $decryptedText"
