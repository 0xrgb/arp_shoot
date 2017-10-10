# arp_shoot

난 불의 군주님을 섬긴다
퍄퍄

## Installation

```
sudo apt install libpcap*
git clone https://github.com/0xrgb/arp_shoot.git
cd arp_shoot
make
```

## Usage

```
sudo ./arp_shoot <interface> <gateway_ip> <target_ip>
```

## 기타

+ `popen` + `grep`을 이용한 IP 찾기
+ C++로 작성했으나 사실상 C 코드임
	+ 리팩토링 해야 함
+ VM 환경에서 테스트가 힘듬
	+ WinPcap으로 재작성
+ `strcspn`을 이용한 `fgets` 뒤의 공백 제거
	+ [StackOverflow](https://stackoverflow.com/questions/2693776/removing-trailing-newline-character-from-fgets-input) 참고
