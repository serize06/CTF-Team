# CTF Team Slack Bot

Slack에서 CTF 에이전트를 호출하여 문제를 풀이하는 봇입니다.

## 설정

### 1. Slack App 생성

1. [Slack API](https://api.slack.com/apps)에서 새 앱 생성
2. **From scratch** 선택 후 앱 이름 입력

### 2. Bot Token Scopes 설정

**OAuth & Permissions** → **Bot Token Scopes**에서 추가:
- `app_mentions:read` - 봇 멘션 읽기
- `chat:write` - 메시지 전송
- `commands` - 슬래시 명령
- `files:write` - 파일 업로드
- `im:history` - DM 읽기
- `im:read` - DM 채널 접근
- `im:write` - DM 전송

### 3. Socket Mode 활성화

**Socket Mode** → Enable Socket Mode → App-Level Token 생성
- Token Name: `ctf-bot-socket`
- Scope: `connections:write`

### 4. Event Subscriptions 설정

**Event Subscriptions** → Enable Events

**Subscribe to bot events**:
- `app_mention`
- `message.im`

### 5. Slash Commands 등록

**Slash Commands** → Create New Command:

| Command | Description |
|---------|-------------|
| `/ctf-agents` | 에이전트 목록 조회 |
| `/ctf-solve` | CTF 문제 풀이 요청 |

### 6. 앱 설치

**Install App** → Install to Workspace

## 실행

```bash
# 의존성 설치
pip install -r requirements.txt

# 환경변수 설정
export SLACK_BOT_TOKEN='xoxb-...'   # Bot User OAuth Token
export SLACK_APP_TOKEN='xapp-...'   # App-Level Token

# 실행
python bot.py
```

## 사용법

### 채널에서 사용

```
@CTF-Bot @director challenges/dreamhack-2026/rsa-magic/ 풀어줘
@CTF-Bot @crypto-rsa 이 RSA 문제 분석해줘
@CTF-Bot @web-sqli SQL Injection 취약점 찾아줘
```

### DM으로 사용

봇에게 직접 DM을 보내면 자동으로 `@director`에게 전달됩니다.

```
challenges/codegate-2026/pwn-easy/ 분석해줘
```

### 슬래시 명령

```
/ctf-agents          # 에이전트 목록
/ctf-solve <경로>    # 문제 풀이
```

## 에이전트 목록

| 팀 | 에이전트 |
|----|---------|
| Director | `@director` |
| Web | `@web-lead`, `@web-sqli`, `@web-xss`, `@web-ssrf`, `@web-auth`, `@web-api`, `@web-upload`, `@web-ssti` |
| Pwn | `@pwn-lead`, `@pwn-bof`, `@pwn-rop`, `@pwn-heap`, `@pwn-fmt`, `@pwn-kernel`, `@pwn-race`, `@pwn-sandbox` |
| Rev | `@rev-lead`, `@rev-static`, `@rev-dynamic`, `@rev-malware`, `@rev-crypto`, `@rev-obfuscation`, `@rev-mobile`, `@rev-game` |
| Forensics | `@forensics-lead`, `@forensics-memory`, `@forensics-network`, `@forensics-disk`, `@forensics-stego`, `@forensics-log`, `@forensics-registry`, `@forensics-artifact` |
| Crypto | `@crypto-lead`, `@crypto-rsa`, `@crypto-symmetric`, `@crypto-hash`, `@crypto-classical`, `@crypto-ecc`, `@crypto-prng`, `@crypto-zk` |
