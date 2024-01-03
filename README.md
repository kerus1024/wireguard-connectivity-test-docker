# Wireguard Connectivity Test Container

컨테이너를 생성하여 Wireguard 프로필의 도달성을 확인합니다.Verify the reachability of the Wireguard profile by creating a container.

이것은 Userspace 구현체인 [wireguard-go](https://github.com/wireguard/wireguard-go) 클라이언트를 사용하여 커널 모듈 활성화가 필요없이 다양한 배포판에서 구동할 수 있습니다. 그러나 여전히 구동 환경은 네트워크를 망치므로 리눅스 격리 플랫폼이 필요합니다. 도커 컨테이너 이미지 기반으로 만들어졌습니다.It can be run on a variety of distributions without the need for kernel module activation using the wireguard-go client, a userspace implementation. However, the operating environment still ruins the network, so a Linux isolation platform is needed. It is built based on Docker container image.


## Concepts

1. (당신)인스턴스는 profile.json 볼륨 마운트 또는 wireguard profile이 위치한 디렉터리, 혹은 지정한 url로부터 profile을 받아오며 환경변수를 통해 정보를 입력받고 컨테이너를 구동합니다.
2. 해당 컨테이너는 입력받은 profile을 사용하여 wireguard를 실제로 연결하여 지정한 서버로 연결을 시도합니다.
3. 연결 성공/실패 결과를 리턴합니다.

## Sample of result

🟢Exit code status with `0` if test is successful
```json
{
  "status": "ok",
  "message": "Hello, world!",
  "total": 3,
  "proceed": 3,
  "proceederror": 0,
  "succeed": 3,
  "workers": 2,
  "results": {
    "con1": {
      "status": "ok",
      "message": "[Worker#1,Subjob#0,10.100.100.3,http_https://cloudflare.com] rtt=269ms"
    },
    "con2": {
      "status": "ok",
      "message": "[Worker#1,Subjob#0,10.100.100.3,http_https://cloudflare.com] rtt=124ms"
    },
    "wgcf": {
      "status": "ok",
      "message": "[Worker#3,Subjob#0,172.16.0.2,http_https://cloudflare.com] rtt=450ms"
    }
  }
}
```

❌Exit code status with `1` if test fails

```json
{
  "status": "error",
  "message": "Hello, world!",
  "total": 4,
  "proceed": 4,
  "proceederror": 1,
  "succeed": 3,
  "workers": 3,
  "results": {
    "con1": {
      "status": "ok",
      "message": "[Worker#3,Subjob#0,10.100.100.3,http_https://cloudflare.com] rtt=139ms"
    },
    "con2": {
      "status": "ok",
      "message": "[Worker#3,Subjob#0,10.100.100.3,http_https://cloudflare.com] rtt=121ms"
    },
    "con3": {
      "status": "error",
      "message": "[Worker#1,Subjob#0,192.168.115.3,http_https://cloudflare.com] HTTP Request was failed... timeout occured"
    },
    "wgcf": {
      "status": "ok",
      "message": "[Worker#2,Subjob#0,172.16.0.2,http_https://cloudflare.com] rtt=440ms"
    }
  }
}
```

## How to use

컨테이너 이미지는 시작과 동시에 전달 받은 환경변수 및 프로필 마운트를 통해 사용자 설정을 진행합니다.
When the container image is started, user settings are made through environment variables received.

### Wireguard Profile File

- docker volume mount를 통해 `/profile.json`을 마운트해야합니다. `-v ./dev/profile.json:/profile.json`
- ⚠️테스트시 사용할 Config는 별도의 실제 사용자가 있는 Peer Configuration이 되는 경우 **실제 사용자의 연결에 충돌이 발생합니다**. 테스트 전용의 Peer profile을 생성하여 연결성 테스트를 하세요.

```json
{
  "wg0": "W0ludGVyZmFjZV0KQWRkcmVzcyA9IDE3Mi4xNy4xNzIuMi8yNApQcml2YXRlS2V5ID0gQUZjK3NCbFA1YXY3STBoby9LTEp3dXdvM3BsZWxKbFhkMys1WmNDakUycz0KCltQZWVyXQpQdWJsaWNLZXkgPSBrMFNkaktzZDZSK2VNZmpvTmduZnFJeUZhWW1yWVRmR1NQdlFmQ3lTdG1VPQpBbGxvd2VkSVBzID0gMTcyLjE3LjE3Mi4xLzMyCkVuZHBvaW50ID0gd2lyZWd1YXJkLmZxZG46NTE4MjA=",
  "wg1": "W0ludGVyZmFjZV0KQWRkcmVzcyA9IDEwLjEwMC4xMDAuMzQuMzQvMjQKUHJpdmF0ZUtleSA9IHdQMlJEZ3h4VE5QcXZWQ3pneXdMSk5qQ090bW9JVlJSdHVTVi9oWndlWG89CgpbUGVlcl0KUHVibGljS2V5ID0gK2JROTJGVlI4MlVUcnJXUld6Qko2QlN4aUNMYmIwZVpwYkJ3aUk3Y2RIQT0KQWxsb3dlZElQcyA9IDEwLjEwMC4xMDAuMzQuMS8zMgpFbmRwb2ludCA9IDEyMy4xMjMuMTIzLjQ6MzIyNA=="
}
```

- 위 wgX에 해당하는 Value값은 wg-quick의 wg0.conf 프로필 파일 내용을 Base64로 인코딩한 값입니다.

#### pass wireguard profile directory

- wg0.conf, wg1.conf, wg-xx.conf 파일이 있는 디렉터리를 `/etc/wireguard`로 마운트하면 해당 프로필을 읽으려고 시도합니다.

#### wireguard profile from web

- `REMOTE_PROFILE_PATH` 환경변수를 사용하면 profile.json을 인터넷에서 다운로드 받아 테스트합니다.

### List of Environment variables

- `/dev/net/tun` 장치와 `NET_ADMIN` Capability가 필요합니다.
- `HEALTHCHECK_METHOD`: (Default) `icmp`
  - `icmp`: `HEALTHCHECK_ENDPOINT`에 보낸 icmp echo-request에 대한 reply을 받을 수 있는 경우 테스트는 성공합니다. 손실율에 관해서는 상관하지 않습니다.
  - `dns`: `HEALTHCHECK_ENDPOINT`:53 네임서버에 DNS Query (udp, type=A) '.' 를 전송하여 어떠한 응답이라도 받을 수 있는 경우 테스트는 성공합니다.
  - `tcp`: `HEALTHCHECK_ENDPOINT` tcp서버에 보낸 SYN의 SYN+ACK를 받을 수 있으면 테스트는 성공합니다.
  - `http`: `HEALTHCHECK_ENDPOINT` url로 보낸 HTTP Request에 대한 어떠한 HTTP 응답헤더를 받을 수 있는 경우 테스트는 성공합니다.
    - 응답받은 서버의 Redirect URL의 재귀처리에 따라서 연결에 성공하였지만 실패하는 경우가 있습니다.
- `HEALTHCHECK_TIMEOUT`: (Default) `3000`ms
  - Wireguard Profile의 접속 요청에 사용될 요청 제한 시간입니다. (dns는 2000ms, icmp는 800ms로 제한되며 해당 설정은 무시됩니다.)
- `HEALTHCHECK_RUNTIMEOUT`: (Default) `10000`ms
  - Wireguard Profile마다 할당되는 재시도를 포함하는 전체 요청 제한 시간입니다. 해당 시간을 초과하면 error로 처리됩니다. (현재 진행되는 요청이 중단되지 않습니다.)
- `HEALTHCHECK_RETRIES`: (Default) `3`
  - 시도할 테스트 횟수입니다. `RUN_TIMEOUT`값에 따라 테스트 횟수가 초과되지 않고 종료될 수 있습니다.
- `WORKER`: (Default) `6` (wireguard parallel)
  - Wireguard Profile이 여러개 있을 때 프로그램은 동시에 여러 연결과 요청을 진행할 수 있습니다. 동시에 처리할 작업의 수를 지정합니다.
  - 연결성 테스트에 사용되는 Wireguard Interface IP와 Peer EndpointIP에 따라서 병렬작업이 단일 작업자로 순차처리 될 수 있습니다.
- `RUNTIMEOUT`: (Default) `30000`ms
  - 테스트 응용프로그램이 종료될 시간입니다. 컨테이너가 시작되고 해당 시간이 경과되면 각 요청에 대한 응답 대기시간과 상관없이 응용프로그램이 종료됩니다. 
- `REMOTE_PROFILE_PATH`: (Default) null
  - profile.json 파일을 외부의 웹사이트로부터 가져오려고 하는 경우 해당 환경변수에 URL을 지정합니다.
- `PROFILE_DATA_SINGLE`: wg-quick 유틸리티에서 사용하는 Wireguard Configuration파일(`wg0.conf`)을 Base64로 Encoding한 것 입니다. 해당 환경변수는 `profile.json`를 마운트하고 싶지 않고 가볍게 바로 실행하고 싶은 경우에 사용합니다.

#### Sample of Running with Docker

```
sudo docker run --rm --name wg-conn-test --rm \
  --device=/dev/net/tun \
  --cap-add=NET_ADMIN \
  -v ./dev/profile.json:/profile.json \
  -e RUNTIMEOUT=60000 \
  -e HEALTHCHECK_ENDPOINT=https://cloudflare.com \
  -e HEALTHCHECK_METHOD=http \
  -e DEBUG_LEVEL=300 \
  ghcr.io/kerus1024/wireguard-connectivity-test-docker:experimental
```

```
sudo docker run --rm --name wg-conn-test --rm \
  --device=/dev/net/tun \
  --cap-add=NET_ADMIN \
  -e REMOTE_PROFILE_PATH=https://google.com/profile.json \
  -e RUNTIMEOUT=30000 \
  -e HEALTHCHECK_ENDPOINT=9.9.9.9 \
  -e HEALTHCHECK_METHOD=dns \
  ghcr.io/kerus1024/wireguard-connectivity-test-docker:experimental
```