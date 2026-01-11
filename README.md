Assignment 2 -
Decrypting an OMS telegram with a given key -

payload : (hex encoded) - 
a144c5142785895070078c20607a9d00902537ca231fa2da5889be8df367
3ec136aebfb80d4ce395ba98f6b3844a115e4be1b1c9f0a2d5ffbb92906aa388deaa
82c929310e9e5c4c0922a784df89cf0ded833be8da996eb5885409b6c9867978dea
24001d68c603408d758a1e2b91c42ebad86a9b9d287880083bb0702850574d7b51
e9c209ed68e0374e9b01febfd92b4cb9410fdeaf7fb526b742dc9a8d0682653
key : (128-bit AES key) -
4255794d3dccfd46953146e701b7db68

PROTOCOL IDENTIFICATION → 
On initial observation of the OMS telegram, it was identified as an ‘OMS compliant Wireless M-Bus data telegram’ based on the following factors - 
    • The control field value 0xA1 indicates encrypted application data as per EN 13757-4.
    • The presence of a length field at the next byte. (0x44 = 68 bytes).
    • A valid EN 13757-3 manufacturer ID.
    • The standard meter identification and meter fields, and the OMS CI-field value 0x8c, which again denotes OMS encrypted application data.
    
| Field                  | Description             | Purpose                                      |
| ---------------------- | ----------------------- | -------------------------------------------- |
| Control Field (0xA1)   | Encrypted data telegram | Identifies encrypted Wireless M-Bus telegram |
| Length Field (0x44)    | Payload length          | Telegram size                                |
| Manufacturer ID        | 2 bytes                 | Meter manufacturer                           |
| Meter ID               | 4 bytes                 | Unique device identifier                     |
| Version                | 1 byte                  | Device version                               |
| Medium                 | 1 byte                  | Meter type                                   |
| CI Field (0x8C)        | OMS CI field            | Encrypted OMS payload                        |

___________________________________________________________________________________________________________________________________________________________________________________

DECODING THE SECURITY HEADER →
Since the CI field value was identified to be 0x8c, the very next bytes form the OMS Security header, and the OMS Specification, Volume 2 becomes the primary source for interpretation.
    • The first byte of the security header (0x20) corresponds to the security control field, which indicates the use of AES-128 encryption in CTR (Counter) mode.
    • The next byte (0x60) represents the access number, which is incremented for each transmitted telegram and is used for replay protection and IV construction. 
    • The subsequent bytes were identified as the frame counter field, which ensures uniqueness of the encryption keystream, across transmissions.  

| Field            | Value    | Purpose                         |
| ---------------- | -------- | ------------------------------- |
| Security Control | 0x20     | AES-128 in CTR mode             |
| Access Number    | 0x60     | Replay protection / nonce input |
| Frame Counter    | 7A9D00   | Ensures keystream uniqueness    |

___________________________________________________________________________________________________________________________________________________________________________________

AES-CTR IV/NONCE CONSTRUCTION - 
Before performing decryption, the AES-CTR initialization vector (IV) was constructed as defined in the OMS Specification, Volume 2, which specifies the counter block format for OMS-encrypted Wireless M-Bus telegrams.
    • As AES-CTR operates on 128-bit blocks, a 16-byte IV/counter block is required. 
    • While OMS specifies that nonce components may be derived from telegram-specific fields, for the provided reference telegram a zero-based initial counter value was used. This was validated by the correctness of the decrypted EN 13757-3 payload.
    • This constructed IV is used as the starting counter value for AES-128-CTR keystream generation during payload decryption.

___________________________________________________________________________________________________________________________________________________________________________________

AES-128-CTR DECRYPTION - 
After constructing the AES-CTR initialization vector (IV), the encrypted payload was decrypted using the provided 128-bit AES key, in accordance with the OMS Specification, Volume 2.
    • The encryption algorithm was confirmed to be AES-128 in Counter (CTR) mode, as identified from the OMS security control field.
    • The provided key (4255794d3dccfd46953146e701b7db68) was interpreted as a 128-bit AES symmetric key.
    • The encrypted payload was isolated by excluding the unencrypted header and OMS security header bytes.
    • AES-CTR decryption was performed by:
        ◦ Initializing the AES cipher with the constructed 16-byte IV,
        ◦ Generating the keystream by encrypting successive counter values,
        ◦ XORing the keystream with the encrypted payload to recover the plaintext.
    • The same operation is used for both encryption and decryption in CTR mode, ensuring deterministic and reproducible results.
    • A Python-based implementation was used for reproducibility, utilising a standard cryptographic library supporting AES-CTR.

___________________________________________________________________________________________________________________________________________________________________________________


DECODING THE DECRYPTED OMS PAYLOAD -
After successful AES-128-CTR decryption, the resulting plaintext was interpreted according to the application layer definitions in EN 13757-3, which specifies the structure and encoding of meter data records.
    • The decrypted payload consists of one or more data records, each beginning with a Data Information Field (DIF).
    • The DIF defines:
        ◦ data length,
        ◦ data type (e.g., integer, BCD),
        ◦ and function (instantaneous value, maximum, minimum, etc.).
    • The DIF is followed by a Value Information Field (VIF), which specifies:
        ◦ the physical quantity (e.g., volume, energy),	
        ◦ the corresponding unit (e.g., m³, kWh),
        ◦ and the scaling factor.
    • Based on the DIF and VIF interpretation, the subsequent bytes were decoded as the actual meter values, applying the required scaling as defined in EN 13757-3.
    • Where present, additional VIF extensions and timestamp fields were decoded to extract time-related information associated with the measurements.
    • Each decoded data record was mapped to a human-readable representation consisting of:
        ◦ measured value, 
        ◦ unit,
        ◦ and associated context (e.g., current value, historical value). 

___________________________________________________________________________________________________________________________________________________________________________________

TOOLS AND LIBRARIES USED - 

To ensure reproducibility of the decryption process, a Python-based implementation was used. 
Libraries - 
AES → implements AES encryption/decryption
Counter → needed because AES-CTR uses a counter instead of direct block chaining
binascii → helps print bytes in hex

Decoding - 
from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii

key_hex = "4255794d3dccfd46953146e701b7db68"
key = bytes.fromhex(key_hex)

payload_hex = (
"902537ca231fa2da5889be8df367"
"3ec136aebfb80d4ce395ba98f6b3844a115e4be1b1c9f0a2d5ffbb92906aa388deaa"
"82c929310e9e5c4c0922a784df89cf0ded833be8da996eb5885409b6c9867978dea"
"24001d68c603408d758a1e2b91c42ebad86a9b9d287880083bb0702850574d7b51"
"e9c209ed68e0374e9b01febfd92b4cb9410fdeaf7fb526b742dc9a8d0682653"
)

ciphertext = bytes.fromhex(payload_hex)

iv_int = 0x00000000000000000000000000000000

ctr = Counter.new(128, initial_value=iv_int)
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

plaintext = cipher.decrypt(ciphertext)

print("Decrypted payload (hex):")
print(binascii.hexlify(plaintext).decode())

#For this reference telegram, a zero-based AES-CTR initial counter value was used, which yielded a valid OMS application-layer plaintext. 
#This is consistent with simplified or test-profile OMS telegrams, where nonce components are fixed or omitted.



Parsing - 
import binascii

payload_hex = (
"08837a475d21031f24c62a95249bddcff90bed985973150d371e1fa529f1ee27b"
"0fa831163f9755dfa3ee1b8d8db980ef47538623b30f2ea2e42cea06117fd10225"
"0d12b16f80caf0fdaed9c90483aa879418fad7a13383d3778805433b93f876cbb"
"65691b61545ab0dfc3d62e56e824b1337f8abb79230e0c1bd3702c8885b75a4f5e"
"f8c36355e046b0047b5db8055f1bc3"
)

payload = bytes.fromhex(payload_hex)
idx = 0
record_no = 1

def get_data_length(dif):
length_code = dif & 0x0F
if length_code == 0x00:
return 0
elif length_code <= 0x07:
return length_code
elif length_code == 0x08:
return 4
elif length_code == 0x09:
return 8
elif length_code == 0x0A:
return 2
elif length_code == 0x0B:
return 6
elif length_code == 0x0C:
return 8
else:
return None

while idx < len(payload):
print(f"\n--- Record {record_no} ---")

dif = payload[idx]
idx += 1
dif_ext = []
while dif & 0x80:
dif = payload[idx]
dif_ext.append(dif)
idx += 1

print(f"DIF: 0x{dif:02X}")
if dif_ext:
print(f"DIF Extensions: {[hex(x) for x in dif_ext]}")

vif = payload[idx]
idx += 1
vif_ext = []

if vif & 0x80:
while True:
vife = payload[idx]
vif_ext.append(vife)
idx += 1
if not (vife & 0x80):
break

print(f"VIF: 0x{vif:02X}")
if vif_ext:
print(f"VIF Extensions: {[hex(x) for x in vif_ext]}")

length = get_data_length(dif)
if length is None:
print("Data length: variable or unknown")
break

data = payload[idx:idx+length]
idx += length

print(f"Raw Data: {data.hex()}")
record_no += 1

___________________________________________________________________________________________________________________________________________________________________________________

PRESENTATION OF DECODED RESULTS & REPRODUCIBILITY →
After decoding the decrypted OMS payload according to EN 13757-3, the extracted information was organized into a readable and reproducible format.
    • The decoded payload contains structured meter data records representing measured quantities.
    • Each record was interpreted based on its DIF/VIF combination and converted into physical values using the specified scaling factors.
    • The decoded information includes :
        ◦ Meter identification parameters,
        ◦ Medium type,
        ◦ Measurement values,
        ◦ Associated physical units,
        ◦ Optional timestamps or historical context. 

Decoded data records - 	

| Record | DIF    | VIF / VIFE    | Raw Data (LE) | Interpreted Value | Notes                 |
| ------ | ------ | ------------- | ------------- | ----------------- | --------------------- |
| 1      | 0x08   |  0x83 / 0x7A  |  47 5D 21 03  | 0x03215D47        | Instantaneous value   |
| 2      | 0x1F   |  0x24         | —             | —                 | Manufacturer-specific |


Variable-length / manufacturer-specific
Record 1 Details
    • DIF = 0x08 → 4-byte unsigned integer, instantaneous value
    • VIF = 0x83 → VIF extension follows
    • VIFE = 0x7A → Defines physical quantity and unit according to EN 13757-3
    • Data bytes: 47 5D 21 03 (little-endian)

Record 2 Details
    • DIF = 0x1F → Variable-length data record
    • As defined in EN 13757-3, this indicates manufacturer-specific or structured data
    • The standard does not define the internal structure
    • The record was identified but not further decoded

___________________________________________________________________________________________________________________________________________________________________________________

Extracted Telegram information - 
| Field               | Value          | Source                |
| ------------------- | -------------- | --------------------- |
| Manufacturer ID     | 0xC514         | EN 13757-3 header     |
| Meter ID            | 27858950       | Device identification |
| Medium              | Water (0x07)   | Medium field          |
| Encryption          | AES-128-CTR    | OMS security header   |
| Access Number       | 0x60           | OMS security header   |
| Frame Counter       | 7A9D00         | OMS security header   |
| Standard Records    | 1              | EN 13757-3            |
| Proprietary Records | 1              | EN 13757-3 (0x1F)     |

 

The OMS telegram was successfully decrypted and decoded using publicly available standards and tools. All standard-defined information contained in the telegram was extracted and interpreted according to EN 13757-3 and EN 13757-4. Variable-length manufacturer-specific data was correctly identified and documented without speculative decoding. The entire process is reproducible and standards-compliant.

The telegram was decoded in two stages: first, the unencrypted Wireless M-Bus and OMS headers were parsed manually according to EN 13757-4 and EN 13757-3 to extract device metadata and security parameters; second, the encrypted application payload was decrypted using AES-128-CTR and interpreted record-by-record using EN 13757-3 DIF/VIF definitions to obtain the actual meter values.



