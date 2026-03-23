# CTF Team Bot System

## Overview
CTF(Capture The Flag) 대회 해결을 위한 AI 봇 팀 시스템입니다.

## Team Structure

```
                    ┌─────────────────┐
                    │  @director      │
                    │  (총괄 부장)    │
                    └────────┬────────┘
                             │
    ┌────────────┬───────────┼───────────┬────────────┐
    │            │           │           │            │
┌───▼───┐   ┌────▼────┐  ┌───▼───┐  ┌────▼────┐  ┌────▼────┐
│@web-  │   │@pwn-    │  │@rev-  │  │@foren-  │  │@crypto- │
│lead   │   │lead     │  │lead   │  │sics-lead│  │lead     │
└───┬───┘   └────┬────┘  └───┬───┘  └────┬────┘  └────┬────┘
    │            │           │           │            │
 전문가들     전문가들     전문가들     전문가들     전문가들
```

## How to Use

### 기본 사용법
```
@director [CTF 문제 설명 또는 파일 경로]
```

Director가 문제를 분석하고 적절한 팀에 위임합니다.

### 특정 팀 직접 호출
```
@web-lead [웹 문제]
@pwn-lead [바이너리 문제]
@rev-lead [리버싱 문제]
@forensics-lead [포렌식 문제]
@crypto-lead [암호 문제]
```

### 특정 전문가 직접 호출
```
@web-sqli [SQL Injection 문제]
@pwn-heap [Heap 익스플로잇 문제]
@crypto-rsa [RSA 문제]
```

## Available Agents

### Director
- `@director` - CTF 총괄 관리, 문제 분류 및 팀 배정

### Web Hacking Team
| Agent | Specialty |
|-------|-----------|
| `@web-lead` | 웹해킹 팀장 |
| `@web-sqli` | SQL Injection |
| `@web-xss` | XSS |
| `@web-ssrf` | SSRF |
| `@web-auth` | 인증/인가 |
| `@web-api` | API 보안 |
| `@web-upload` | 파일 업로드 |
| `@web-ssti` | SSTI |

### Pwnable Team
| Agent | Specialty |
|-------|-----------|
| `@pwn-lead` | 포너블 팀장 |
| `@pwn-bof` | Buffer Overflow |
| `@pwn-rop` | ROP/Gadgets |
| `@pwn-heap` | Heap Exploitation |
| `@pwn-fmt` | Format String |
| `@pwn-kernel` | Kernel Exploit |
| `@pwn-race` | Race Condition |
| `@pwn-sandbox` | Sandbox Escape |

### Reversing Team
| Agent | Specialty |
|-------|-----------|
| `@rev-lead` | 리버싱 팀장 |
| `@rev-static` | 정적 분석 |
| `@rev-dynamic` | 동적 분석 |
| `@rev-malware` | 악성코드 분석 |
| `@rev-crypto` | 암호 리버싱 |
| `@rev-obfuscation` | 난독화 해제 |
| `@rev-mobile` | 모바일 앱 |
| `@rev-game` | 게임 해킹 |

### Forensics Team
| Agent | Specialty |
|-------|-----------|
| `@forensics-lead` | 포렌식 팀장 |
| `@forensics-memory` | 메모리 포렌식 |
| `@forensics-network` | 네트워크 포렌식 |
| `@forensics-disk` | 디스크 포렌식 |
| `@forensics-stego` | 스테가노그래피 |
| `@forensics-log` | 로그 분석 |
| `@forensics-registry` | 레지스트리 |
| `@forensics-artifact` | 아티팩트 분석 |

### Crypto Team
| Agent | Specialty |
|-------|-----------|
| `@crypto-lead` | 암호학 팀장 |
| `@crypto-rsa` | RSA 공격 |
| `@crypto-symmetric` | 대칭키 암호 |
| `@crypto-hash` | 해시 공격 |
| `@crypto-classical` | 고전 암호 |
| `@crypto-ecc` | 타원곡선 암호 |
| `@crypto-prng` | PRNG |
| `@crypto-zk` | 영지식 증명 |

## Directory Structure

```
CTF-Team/
├── .claude/
│   ├── agents/          # 봇 정의 파일들
│   ├── settings.json    # 권한 설정
│   └── CLAUDE.md        # 이 파일
├── challenges/          # CTF 문제 작업 디렉토리 (대회/문제 단위)
│   ├── dreamhack-2026/  # 대회명
│   │   ├── rsa-magic/   # 문제명 (복합 문제도 한 폴더에서 관리)
│   │   │   ├── challenge.py
│   │   │   ├── flag.enc
│   │   │   └── solve.py
│   │   └── web-revenge/
│   │       ├── app.py
│   │       └── notes.md
│   └── codegate-2026/
│       └── kernel-pwn/
├── tools/               # 공용 스크립트
└── writeups/            # Write-up 저장소
```

### 문제 디렉토리 관리 규칙

1. **대회 단위 폴더**: `challenges/<대회명>/` (예: `dreamhack-2026`, `codegate-2026`)
2. **문제 단위 폴더**: `challenges/<대회명>/<문제명>/` — 모든 관련 파일을 한 곳에
3. **복합 문제 협업**: 여러 팀이 같은 문제 폴더에서 작업 가능 (crypto+web 등)
4. **연습 문제**: `challenges/practice/<문제명>/` 으로 관리

## Agent Teams (Split Pane 모드)

Agent Teams 기능이 활성화되어 있습니다. 여러 에이전트가 각각 별도의 터미널 패널에서 동시에 작업하는 모습을 볼 수 있습니다.

### 사용법
```
# tmux 안에서 claude를 실행하면 자동으로 split pane 모드
tmux
claude --teammate-mode tmux

# 또는 in-process 모드 (tmux 없이)
claude --teammate-mode in-process
```

### 팀 생성 예시
```
CTF 문제를 풀기 위한 agent team을 만들어줘.
- crypto 담당 1명
- web 담당 1명
- pwn 담당 1명
각자 challenges/dreamhack-2026/ 폴더의 문제를 분석해줘.
```

### 조작법
- **Shift+Down**: 팀원 간 전환 (in-process 모드)
- **Ctrl+T**: 태스크 리스트 토글
- **클릭**: 해당 팀원 패널로 이동 (split pane 모드)

## Tips

1. **문제 파일 제공**: 바이너리, 소스코드, pcap 파일 등을 `challenges/<대회>/<문제>/`에 저장
2. **정보 제공**: 문제 설명, 힌트, 서버 주소 등을 함께 제공
3. **단계별 접근**: Director가 적절한 팀으로 라우팅 (복합 문제는 여러 팀 동시 투입)
4. **Write-up 저장**: 해결된 문제는 writeups/에 기록

## Example

```
사용자: @director challenges/dreamhack-2026/rsa-magic/ 풀어줘

Director: RSA + 웹 복합 문제입니다. crypto-lead와 web-lead에게 동시 위임합니다.

crypto-lead: e=3으로 작은 지수 공격이 가능합니다. crypto-rsa 전문가에게 위임합니다.
web-lead: API 엔드포인트에서 암호문을 추출합니다.

crypto-rsa: Hastad's Broadcast Attack 적용...
[분석 및 풀이]
플래그: FLAG{example_flag}
```
