# CTF Team Bot System

CTF(Capture The Flag) 대회 해결을 위한 AI 에이전트 팀 시스템입니다.

## Quick Start

### 1. 요구사항

- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) 설치 필요
- Anthropic API 키 또는 Claude Pro/Max 구독

### 2. 설치

```bash
git clone https://github.com/your-repo/CTF-Team.git
cd CTF-Team
```

### 3. 사용

```bash
claude
```

Claude Code 실행 후 에이전트 호출:

```
@director challenges/dreamhack-2026/rsa-magic/ 분석해줘
```

## Team Structure

```
                    ┌─────────────────┐
                    │    @director    │
                    │   (CTF 총괄)    │
                    └────────┬────────┘
                             │
    ┌────────────┬───────────┼───────────┬────────────┐
    │            │           │           │            │
┌───▼───┐   ┌────▼────┐  ┌───▼───┐  ┌────▼────┐  ┌────▼────┐
│ @web- │   │ @pwn-   │  │ @rev- │  │@foren-  │  │@crypto- │
│ lead  │   │ lead    │  │ lead  │  │sics-lead│  │ lead    │
└───┬───┘   └────┬────┘  └───┬───┘  └────┬────┘  └────┬────┘
    │            │           │           │            │
 웹해킹       포너블       리버싱      포렌식        암호학
 전문가들     전문가들     전문가들     전문가들     전문가들
```

## Available Agents

| Team | Lead | Specialists |
|------|------|-------------|
| **Web** | `@web-lead` | `@web-sqli` `@web-xss` `@web-ssrf` `@web-auth` `@web-api` `@web-upload` `@web-ssti` |
| **Pwn** | `@pwn-lead` | `@pwn-bof` `@pwn-rop` `@pwn-heap` `@pwn-fmt` `@pwn-kernel` `@pwn-race` `@pwn-sandbox` |
| **Rev** | `@rev-lead` | `@rev-static` `@rev-dynamic` `@rev-malware` `@rev-crypto` `@rev-obfuscation` `@rev-mobile` `@rev-game` |
| **Forensics** | `@forensics-lead` | `@forensics-memory` `@forensics-network` `@forensics-disk` `@forensics-stego` `@forensics-log` `@forensics-registry` `@forensics-artifact` |
| **Crypto** | `@crypto-lead` | `@crypto-rsa` `@crypto-symmetric` `@crypto-hash` `@crypto-classical` `@crypto-ecc` `@crypto-prng` `@crypto-zk` |

## Usage Examples

### Director에게 문제 분석 요청
```
@director challenges/codegate-2026/web-challenge/ 풀어줘
```

### 특정 팀에 직접 요청
```
@crypto-lead 이 RSA 문제 분석해줘
@web-lead SQL Injection 취약점 찾아줘
```

### 특정 전문가에게 직접 요청
```
@pwn-heap Use-After-Free 취약점 분석해줘
@crypto-rsa e=3 공격 가능한지 확인해줘
```

## Directory Structure

```
CTF-Team/
├── .claude/
│   ├── agents/          # 에이전트 정의 파일
│   ├── settings.json    # 권한 설정
│   └── CLAUDE.md        # 프로젝트 컨텍스트
├── challenges/          # CTF 문제 작업 디렉토리
│   ├── <대회명>/
│   │   └── <문제명>/
│   └── practice/        # 연습 문제
├── tools/               # 공용 스크립트
└── writeups/            # Write-up 저장소
```

### 문제 추가하기

1. 문제 디렉토리 생성:
```bash
mkdir -p challenges/dreamhack-2026/new-challenge
```

2. 문제 파일 복사:
```bash
cp ~/Downloads/challenge.zip challenges/dreamhack-2026/new-challenge/
cd challenges/dreamhack-2026/new-challenge/
unzip challenge.zip
```

3. 분석 요청:
```
@director challenges/dreamhack-2026/new-challenge/ 분석해줘
```

## Tips

- **복합 문제**: Director가 자동으로 여러 팀에 동시 위임 (예: crypto+web)
- **정보 제공**: 문제 설명, 힌트, 서버 주소를 함께 알려주면 더 정확한 분석 가능
- **Write-up**: 해결된 문제는 `writeups/`에 기록 권장

## Troubleshooting

### "agent not found" 오류
- `.claude/agents/` 디렉토리가 있는지 확인
- 프로젝트 루트에서 `claude` 실행했는지 확인

### 에이전트가 도구를 못 쓸 때
- `.claude/settings.json`에서 권한 확인
- 필요한 도구가 설치되어 있는지 확인 (예: `pwntools`, `volatility`)

## License

MIT
