# Wireguard Connectivity Test Container

컨테이너를 생성하여 Wireguard 프로필의 도달성을 확인합니다.Verify the reachability of the Wireguard profile by creating a container.

이것은 Userspace 구현체인 [wireguard-go](https://github.com/Wireuard/wireguard-go) 클라이언트를 사용하여 커널 모듈 활성화가 필요없이 다양한 배포판에서 구동할 수 있습니다. 그러나 여전히 구동 환경은 네트워크를 망치므로 리눅스 격리 플랫폼이 필요합니다. 도커 컨테이너 이미지 기반으로 만들어졌습니다.It can be run on a variety of distributions without the need for kernel module activation using the wireguard-go client, a userspace implementation. However, the operating environment still ruins the network, so a Linux isolation platform is needed. It is built based on Docker container image.


## Concepts

1. (당신)인스턴스는 환경변수를 통해 정보를 입력받고 컨테이너를 구동합니다.
    - (Your) instance receives information through environment variables and runs the container.
2. 컨테이너 애플리케이션은 입력 받은 Wireguard Config를 사용하여 Wireguard peer에 연결합니다.
    - The container application connects to the Wireguard peer using the input Wireguard Config.
3. Wireguard tunnel을 통해 사용자로부터 입력받은 Health Check Endpoint에 도달할 수 있는지 연결을 확인합니다.
    - Check the connection to see if the Health Check Endpoint entered by the user can be reached through the Wireguard tunnel.
4. 컨테이너 애플리케이션이 종료되고 결과를 리턴받습니다.
   - The container application terminates and the results are returned.

## Sample of result

🟢Exit code status with `0` if test is successful
```
{
    "result": "ok",
    "message": "32 bytes from 1.1.1.1: icmp_seq=0 time=22.844702ms\n"
}
```

❌Exit code status with `1` if test fails

```
{
    "result": "error",
    "message": "something is wrong"
}
```

## How to use

컨테이너 이미지는 시작과 동시에 전달 받은 환경변수를 통해 사용자 설정을 진행합니다.
When the container image is started, user settings are made through environment variables received.

### List of Environment variables

- `WG_CONFIG_DATA`: wg-quick 유틸리티에서 사용하는 Wireguard Configuration파일(wg0.conf)을 Base64로 Encoding한 것 입니다.
  - ⚠️테스트시 사용할 Config는 별도의 실제 사용자가 있는 Peer Configuration이 되는 경우 **실제 사용자의 연결에 충돌이 발생합니다**. 테스트 전용의 Peer를 생성하여 연결성 테스트를 하세요.
- `HEALTH_CHECK_METHOD`= (Default) `icmp`
  - `icmp`: `HEALTH_CHECK_ENDPOINT`에 보낸 icmp echo-request에 대한 reply을 받을 수 있는 경우 테스트는 성공합니다. 손실율에 관해서는 상관하지 않습니다.
  - `dns`: `HEALTH_CHECK_ENDPOINT`:53 네임서버에 DNS Query (type=A) '.' 를 전송하여 어떠한 응답이라도 받을 수 있는 경우 테스트는 성공합니다.
  - `tcp`: `HEALTH_CHECK_ENDPOINT` tcp서버에 보낸 SYN의 SYN+ACK를 받을 수 있으면 테스트는 성공합니다.
  - `http`: `HEALTH_CHECK_ENDPOINT` url로 보낸 HTTP Request에 대한 어떠한 HTTP 응답헤더를 받을 수 있는 경우 테스트는 성공합니다.
    - Redirect URL에 따라서 실패하는 경우가 있습니다.
- `HEALTH_CHECK_ENDPOINT`: (Default)`1.0.0.1`
  - 테스트에 사용할 원격 서버 주소입니다. 대상은 METHOD 유형에 따라 포맷이 다릅니다.
- `HEALTH_CHECK_RETRIES`: (Default) `5`
  - 시도할 테스트 횟수입니다. `RUN_TIMEOUT`값에 따라 테스트 횟수가 초과되지 않고 종료될 수 있습니다.
- `RUN_TIMEOUT`: (Default) `20`
  - 테스트 응용프로그램이 종료될 시간입니다. 컨테이너가 시작되고 해당 시간이 경과되면 각 요청에 대한 응답 대기시간과 상관없이 응용프로그램이 종료됩니다. 
- `LABEL`
  - 출력되는 json field에 환경변수로 받은 값을 추가할 수 있습니다.
  
**테스트 주기는 `RUN_TIMEOUT` / `HEALTH_CHECK_RETRIES` 값과 관련됩니다.**

- `/dev/net/tun` 장치와 `NET_ADMIN` Capability가 필요합니다.
- `HEALTH_CHECK_ENDPOINT`에 도메인 이름을 넣는 경우 Wireguard Configuration의 Interface.DNS에 영향을 받습니다.

#### Sample of Running with Docker

```
sudo docker run --rm --cap-add=NET_ADMIN --device=/dev/net/tun \
  -e HEALTH_CHECK_METHOD=icmp \
  -e RUN_TIMEOUT=30 \
  -e HEALTH_CHECK_ENDPOINT=8.8.8.8 \
  -e WG_CONFIG_DATA=W0ludGVyZmFjZV0KQWRkcmVzcyA9IDE3Mi4zMS4wLjIKRE5TID0gMS4xLjEuMSwxLjAuMC4xClByaXZhdGVLZXkgPSBEOVE4dDN5S3VqQmVGTU1yaUFoanI0SFdGcFUrdUNLdGhtbFBvcTVRenlVPQoKW1BlZXJdCkFsbG93ZWRJUHMgPSAwLjAuMC4wLzAKRW5kcG9pbnQgPSAxNjIuMTU5LjE5Mi4xOjIwNDgKUHVibGljS2V5ID0gN0QwVmZqOWxQUWg4a2dPdWZ0UHlmWkhKb2RHS0ZPNWs3UXBLWUY2Y0J3ND0= \
  ghcr.io/kerus1024/wireguard-connectivity-test-docker:1
```

#### Sample of kubernetes pod

pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: static-web
spec:
  restartPolicy: Never
  containers:
    - name: web
      image: wireguard-connectivity-test-docker:1
      env:
      - name: WG_CONFIG_DATA
        value: W0ludGVyZmFjZV0KQWRkcmVzcyA9IDE3Mi4zMS4wLjIKRE5TID0gMS4xLjEuMSwxLjAuMC4xClByaXZhdGVLZXkgPSBEOVE4dDN5S3VqQmVGTU1yaUFoanI0SFdGcFUrdUNLdGhtbFBvcTVRenlVPQoKW1BlZXJdCkFsbG93ZWRJUHMgPSAwLjAuMC4wLzAKRW5kcG9pbnQgPSAxNjIuMTU5LjE5Mi4xOjIwNDgKUHVibGljS2V5ID0gN0QwVmZqOWxQUWg4a2dPdWZ0UHlmWkhKb2RHS0ZPNWs3UXBLWUY2Y0J3ND0=
      - name: HEALTH_CHECK_METHOD
        value: dns
      - name: HEALTH_CHECK_ENDPOINT
        value: 168.126.63.1
      - name: HEALTH_CHECK_RETRIES
        value: "1"
      - name: RUN_TIMEOUT
        value: "3"
      securityContext:
        capabilities:
          add: ["NET_ADMIN"]
      volumeMounts:
        - mountPath: /dev/net/tun
          name: test-volume
  volumes:
    - name: test-volume
      hostPath:
        path: /dev/net/tun
```

cronjob:

```
😅
```




##### TO-DO Features
###### Test Callback
###### check container uid
###### lightweighting