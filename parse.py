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
