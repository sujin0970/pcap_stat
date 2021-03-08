# BoB9_수료과제

## 과제
pcap file로부터 packet을 읽어서 IP별 송신 패킷 갯수, 수신 패킷 갯수, 송신 패킷 바이트, 수신 패킷 바이트를 출력하는 프로그램을 작성하라.

## 실행
syntax : packet-stat 'pcap file' <br>
sample : packet-stat test.pcap

## 라이브러리 설치
$ cd github_download_folder
$ sudo apt-get install libpcap-dev <br>
$ wget http://34.86.103.226:8000/pcapplusplus.tar.xz (pcapplusplus 라이브러리 다운로드)<br>
$ tar -xvf pcapplusplus.tar.xz <br>
$ cd pcapplusplus  <br>
$ sudo ./install.sh  <br> 
===>   Installation complete!   <br>

## 소스코드 실행
*** makefile의 pcapplusplus.mk 경로는 우분투버전에 따라 다를 수 있으니, 주의할 것 *** <br>
$ cd ..<br>
$ cd pcap_stat_src  <br>
$ make  <br>
$ sudo ./packet-stat test.pcap <br>
*** 여러 pcap 파일을 실행시킬 수 있다 ***

## 참고 사항
비오비9기 해커톤 'Packet Sniffer' (김경환교육생, 서예진교육생, 본인이 팀을 이뤄 수행함)를 참고하여 본 과제를 수행하였습니다. <br>
HTTP, SMTP, FTP 패킷을 읽어 패킷데이터를 분석하는 프로젝트입니다.<br>
해커톤당시의 repo는 sujin0970/pcap_analysis 입니다.
