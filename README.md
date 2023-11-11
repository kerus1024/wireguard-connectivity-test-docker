# Wireguard Connectivity Test Container

컨테이너를 생성하여 Wireguard 프로필의 도달성을 확인합니다.Verify the reachability of the Wireguard profile by creating a container.

이것은 Userspace 구현체인 [wireguard-go](https://github.com/wireguard/wireguard-go) 클라이언트를 사용하여 커널 모듈 활성화가 필요없이 다양한 배포판에서 구동할 수 있습니다. 그러나 여전히 구동 환경은 네트워크를 망치므로 리눅스 격리 플랫폼이 필요합니다. 도커 컨테이너 이미지 기반으로 만들어졌습니다.It can be run on a variety of distributions without the need for kernel module activation using the wireguard-go client, a userspace implementation. However, the operating environment still ruins the network, so a Linux isolation platform is needed. It is built based on Docker container image.


## Concepts

1. (당신)인스턴스는 profile.json 볼륨 마운트 또는 wireguard profile이 위치한 디렉터리, 혹은 지정한 url로부터 profile을 받아오며 환경변수를 통해 정보를 입력받고 컨테이너를 구동합니다.


## Sample of result

🟢Exit code status with `0` if test is successful
```
{"status":"ok","message":"Hello, world!","results":{"con1":{"status":"ok","message":"success"},"con2":{"status":"error","message":"timeout context"},"con3":{"status":"error","message":"timeout context"}}}
```

❌Exit code status with `1` if test fails

```
{"status":"error","message":"all profile are not working.","results":{"con1":{"status":"error","message":"timeout context"},"con2":{"status":"error","message":"timeout context"},"con3":{"status":"error","message":"timeout context"}}}
```

## How to use

컨테이너 이미지는 시작과 동시에 전달 받은 환경변수를 통해 사용자 설정을 진행합니다.
When the container image is started, user settings are made through environment variables received.

### List of Environment variables

- `/dev/net/tun` 장치와 `NET_ADMIN` Capability가 필요합니다.
- `HEALTH_CHECK_ENDPOINT`에 도메인 이름을 넣는 경우 Wireguard Configuration의 Interface.DNS에 영향을 받습니다.

#### Sample of Running with Docker

```
sudo docker run --rm --cap-add=NET_ADMIN --device=/dev/net/tun \
  -e HEALTH_CHECK_METHOD=icmp \
  -e RUN_TIMEOUT=30 \
  -e HEALTH_CHECK_ENDPOINT=8.8.8.8 \
  ghcr.io/kerus1024/wireguard-connectivity-test-docker:latest
```
