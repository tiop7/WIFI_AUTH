# WiFi Authentication : Beacon Manipulation
## Overview
![image](https://github.com/tiop7/WIFI_AUTH/assets/136809317/323d2250-44ff-4710-93f3-4d01e3c45a85)
- AP가 Beacon frame에 Cert. & Signature를 추가하여 Client에 전달.
- Client는 전달받은 Cert. & Signature를 인증하고 Connection 진행.
<br>

## Frame Structure
![image](https://github.com/tiop7/WIFI_AUTH/assets/136809317/0f971da9-2088-4459-b9cb-e22416d74096)

<br>

## Implementation Status
- Python Scapy를 이용하여 Beacon 조작 및 전송.
  - Scapy : https://scapy.readthedocs.io/en/latest/index.html(https://scapy.readthedocs.io/en/latest/index.html)
  - Python 3.10 기준으로 작성.
- Client 측에서 Beacon 수신하는 코드 분석.


<br>

## Basic Usage
- Install Scapy
```
> pip install scapy
```

<br>

- Edit the code
```
IFACE = "YOUR-WiFi-INTERFACE"  # WiFi device name에 맞게 수정.

...

with open("./certs/rsa_512.crt", "rb") as cert_file:  # 사용하고자 하는 Cert. 경로로 수정.
    cert_data = cert_file.read()

...

with open('./keys/private_key_rsa_512.pem', 'rb') as key_file:  # 사용하고자 하는 Key 경로로 수정.
    private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

```

<br>

- Run
```
> python rsa_scapy_with_cert_sig.py
```

<br>

- Capture the manipulated beacons

![image](https://github.com/tiop7/WIFI_AUTH/assets/136809317/2d8d0bb2-5152-447f-9c4b-c03cd0b40ea7)


<br>

## Experiment & Result
![image](https://github.com/tiop7/WIFI_AUTH/assets/136809317/f3855a2a-b5f3-4d31-beba-410445a60e7f)
<br>

![image](https://github.com/tiop7/WIFI_AUTH/assets/136809317/c76fadf0-6d18-4d03-b2b1-a423fe5973ba)


