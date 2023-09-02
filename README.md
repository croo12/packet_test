## 패킷 찍어보기

##### 사용한 crate
- pnet = "0.34"
    - 패킷 캡쳐용
- clap = "4.0"
    - 명령어 parsing 쉽게 하려고 사용.
---

##### 현재 분리해 본 것

###### DataLink
- EthernetIIFrame

###### Network
- IPv4
- ARP

###### Transport
- IPv4::TCP
- IPv4::UDP