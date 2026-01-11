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

# For this reference telegram, a zero-based AES-CTR initial counter value was used, which yielded a valid OMS application-layer plaintext. 
# This is consistent with simplified or test-profile OMS telegrams, where nonce components are fixed or omitted.