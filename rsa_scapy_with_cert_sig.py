from scapy.all import *
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography import x509
import time

netSSID = 'UniverseTest'

dot11 = Dot11(type=0, subtype=8, addr1 = 'ff:ff:ff:ff:ff:ff', addr2 = '11:11:11:11:11:12', addr3 = '22:22:22:22:22:22')
beacon = Dot11Beacon(cap='ESS+privacy')
essid = Dot11Elt(ID='SSID', info=netSSID, len=len(netSSID))

rsn = Dot11Elt(ID='RSNinfo', info=(
'\x01\x00'
'\x00\x0f\xac\x02'
'\x02\x00'
'\x00\x0f\xac\x04'
'\x00\x0f\xac\x02'
'\x01\x00'
'\x00\x0f\xac\x02'
'\x00\x00'))

# 인증서 로드 & 파싱
with open("./rsa_512.crt", "rb") as cert_file:
    cert_data = cert_file.read()
# cert = x509.load_pem_x509_certificate(cert_data, default_backend())

# 키 로드
with open('./private_key_rsa_512.pem', 'rb') as private_key_file:
    private_key_pem = private_key_file.read()
    
# 키 생성
private_key = serialization.load_pem_private_key(
    private_key_pem, password=None, backend=default_backend()
)

frame = RadioTap()/dot11/beacon/essid/rsn/'certS'/cert_data/'certE'


# Signature 생성부

message = bytes(frame)

signature = private_key.sign(
    message, padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)


frame = frame/'sigS'/signature/'sigE'

frame.show()


# Delay 측정
print('Beacon started\n')

for i in range(0,20) :
    start = time.time()
    sendp(frame, iface='Wi-Fi', inter=0.100, loop=1, count=1)
    end = time.time()
    btime = (end-start)*1000
    print(f"{btime:.7f} ms")

# sendp(frame, iface='Wi-Fi', inter=0.100, loop=1, count=1)

# 서명 저장
# with open("./signature_frame.bin", "wb") as file:
#    file.write(signature)




# -------- 검증코드 -------- #
"""
# 공개키 로드
with open('./public_key.pem', 'rb') as public_key_file:
    public_key_pem = public_key_file.read()

 공개키 생성
public_key = serialization.load_pem_public_key(
    public_key_pem, backend=default_backend()
)

# 서명 로드
with open("./signature_frame.bin", "rb") as file:
    signature_frame = file.read()


 서명 검증
try:
    public_key.verify(
        signature_frame, message, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("서명이 유효합니다.")
except InvalidSignature:
    print("서명이 유효하지 않습니다.")
"""

