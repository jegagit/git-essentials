
from reportlab.pdfgen import canvas
from reportlab.graphics.barcode import code128
from reportlab.lib.units import mm
from reportlab.lib.colors import black, gray

def draw_3d_barcode(pdf, barcode_text, x, y, width, height):
    # Generate the barcode
    barcode = code128.Code128(barcode_text, barWidth=width / 100.0, barHeight=height)
    
    # Create a "shadow" to mimic 3D by drawing the barcode slightly offset
    shadow_offset = 1 * mm
    barcode.drawOn(pdf, x + shadow_offset, y - shadow_offset)
    
    # Draw the main barcode in black
    pdf.setFillColor(black)
    barcode.drawOn(pdf, x, y)

# Create PDF canvas
pdf_filename = "3d_barcode.pdf"
pdf = canvas.Canvas(pdf_filename)

# Define barcode parameters
barcode_text = "3D1234567890"
barcode_x = 50 * mm
barcode_y = 150 * mm
barcode_width = 40 * mm
barcode_height = 20 * mm

# Set shadow color
pdf.setFillColor(gray)
draw_3d_barcode(pdf, barcode_text, barcode_x, barcode_y, barcode_width, barcode_height)

# Save the PDF
pdf.save()

print(f"3D barcode saved to {pdf_filename}")

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


===================================
#public key is in OpenSSH format (begins with something like 'ssh-rsa', 'ssh-dss', etc.), you can use the load_ssh_public_key method. 
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def get_ssh_public_key_fingerprint(public_key_str):
    try:
        # Load the public key from the string
        public_key = load_ssh_public_key(public_key_str.encode(), backend=default_backend())

        # Serialize the public key to bytes
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )

        # Calculate the fingerprint
        fingerprint_bytes = hashlib.md5(public_bytes).digest()

        # Convert the fingerprint to a hexadecimal string
        fingerprint_hex = ':'.join(format(b, '02x') for b in fingerprint_bytes)
        return fingerprint_hex

    except ValueError as e:
        # Handle the case where the string is not a valid public key
        print(f"Error parsing public key: {str(e)}")
        return None

# Your public key string here; it should be a single line and start with 'ssh-rsa', 'ssh-dss', etc.
public_key_str = """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."""

fingerprint = get_ssh_public_key_fingerprint(public_key_str)
if fingerprint:
    print(f'Fingerprint: {fingerprint}')
else:
    print('Failed to generate fingerprint.')

=============================
#!/bin/bash

# Path to the authorized_keys file
AUTHORIZED_KEYS_FILE="/path/to/authorized_keys"

# Temporary file for individual keys
TEMP_KEY_FILE=$(mktemp)

# Ensure the temporary file is deleted upon script exit
trap "rm -f $TEMP_KEY_FILE" EXIT

# Read the authorized_keys file line by line
while IFS= read -r line; do
    # Skip empty lines or comments
    if [[ "$line" =~ ^$ ]] || [[ "$line" =~ ^# ]]; then
        continue
    fi

    # Write the key to the temporary file
    echo "$line" > "$TEMP_KEY_FILE"

    # Get the fingerprint using ssh-keygen
    ssh-keygen -l -f "$TEMP_KEY_FILE"
done < "$AUTHORIZED_KEYS_FILE"






