from scapy.all import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature
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
with open("./ecdsa_256.crt", "rb") as cert_file:
    cert_data = cert_file.read()
# cert = x509.load_pem_x509_certificate(cert_data, default_backend())

# ECDSA 키 로드 & 생성
with open("./private_key_ecdsa_p256.pem", "rb") as key_file:
    private_key = load_pem_private_key(key_file.read(), password=None, backend=default_backend())


frame = RadioTap()/dot11/beacon/essid/rsn/'certS'/cert_data/'certE'


# Signature 생성부

message = bytes(frame)

signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

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










