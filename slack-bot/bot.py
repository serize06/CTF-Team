#!/usr/bin/env python3
"""
CTF Team Slack Bot
Slack에서 CTF 에이전트(@director, @crypto-lead 등)를 호출하여 문제 풀이
"""

import os
import re
import subprocess
import tempfile
import json
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

# Slack 앱 초기화
app = App(token=os.environ.get("SLACK_BOT_TOKEN"))

# 지원하는 에이전트 목록
AGENTS = {
    # Director
    "director": "CTF 총괄 관리, 문제 분류 및 팀 배정",
    # Web Team
    "web-lead": "웹해킹 팀장",
    "web-sqli": "SQL Injection",
    "web-xss": "XSS",
    "web-ssrf": "SSRF",
    "web-auth": "인증/인가",
    "web-api": "API 보안",
    "web-upload": "파일 업로드",
    "web-ssti": "SSTI",
    # Pwn Team
    "pwn-lead": "포너블 팀장",
    "pwn-bof": "Buffer Overflow",
    "pwn-rop": "ROP/Gadgets",
    "pwn-heap": "Heap Exploitation",
    "pwn-fmt": "Format String",
    "pwn-kernel": "Kernel Exploit",
    "pwn-race": "Race Condition",
    "pwn-sandbox": "Sandbox Escape",
    # Rev Team
    "rev-lead": "리버싱 팀장",
    "rev-static": "정적 분석",
    "rev-dynamic": "동적 분석",
    "rev-malware": "악성코드 분석",
    "rev-crypto": "암호 리버싱",
    "rev-obfuscation": "난독화 해제",
    "rev-mobile": "모바일 앱",
    "rev-game": "게임 해킹",
    # Forensics Team
    "forensics-lead": "포렌식 팀장",
    "forensics-memory": "메모리 포렌식",
    "forensics-network": "네트워크 포렌식",
    "forensics-disk": "디스크 포렌식",
    "forensics-stego": "스테가노그래피",
    "forensics-log": "로그 분석",
    "forensics-registry": "레지스트리",
    "forensics-artifact": "아티팩트 분석",
    # Crypto Team
    "crypto-lead": "암호학 팀장",
    "crypto-rsa": "RSA 공격",
    "crypto-symmetric": "대칭키 암호",
    "crypto-hash": "해시 공격",
    "crypto-classical": "고전 암호",
    "crypto-ecc": "타원곡선 암호",
    "crypto-prng": "PRNG",
    "crypto-zk": "영지식 증명",
}

# 에이전트 멘션 패턴 (@agent-name)
AGENT_PATTERN = re.compile(r"@(" + "|".join(AGENTS.keys()) + r")\b", re.IGNORECASE)


def call_claude_agent(agent_type: str, prompt: str, working_dir: str = None) -> str:
    """
    Claude Code CLI를 통해 에이전트 호출
    """
    if working_dir is None:
        working_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Claude Code CLI 명령 구성
    cmd = [
        "claude",
        "--print",  # 결과만 출력
        "--dangerously-skip-permissions",  # 비대화형 모드
    ]

    # 에이전트 타입에 따른 프롬프트 구성
    full_prompt = f"@{agent_type} {prompt}"

    try:
        result = subprocess.run(
            cmd,
            input=full_prompt,
            capture_output=True,
            text=True,
            timeout=300,  # 5분 타임아웃
            cwd=working_dir,
        )
        return result.stdout or result.stderr or "응답 없음"
    except subprocess.TimeoutExpired:
        return "에이전트 응답 시간 초과 (5분)"
    except Exception as e:
        return f"에이전트 호출 오류: {str(e)}"


def parse_agent_request(text: str) -> tuple[str, str] | None:
    """
    메시지에서 에이전트 멘션과 프롬프트 추출
    Returns: (agent_type, prompt) or None
    """
    match = AGENT_PATTERN.search(text)
    if match:
        agent = match.group(1).lower()
        # 에이전트 멘션 이후의 텍스트를 프롬프트로 사용
        prompt = text[match.end():].strip()
        return (agent, prompt)
    return None


@app.event("app_mention")
def handle_app_mention(event, say, client):
    """봇이 멘션되었을 때 처리"""
    text = event.get("text", "")
    channel = event.get("channel")
    thread_ts = event.get("thread_ts") or event.get("ts")

    # 에이전트 요청 파싱
    request = parse_agent_request(text)

    if request:
        agent_type, prompt = request

        # 처리 중 메시지
        say(
            text=f":robot_face: `@{agent_type}` 에이전트가 분석 중입니다...",
            thread_ts=thread_ts,
        )

        # 에이전트 호출
        response = call_claude_agent(agent_type, prompt)

        # 응답 전송 (길면 파일로)
        if len(response) > 3000:
            client.files_upload_v2(
                channel=channel,
                content=response,
                filename=f"{agent_type}_response.md",
                title=f"@{agent_type} 응답",
                thread_ts=thread_ts,
            )
        else:
            say(text=response, thread_ts=thread_ts)
    else:
        # 에이전트 목록 안내
        agent_list = "\n".join([f"• `@{k}` - {v}" for k, v in list(AGENTS.items())[:10]])
        say(
            text=f"CTF Team Bot입니다! 에이전트를 멘션해주세요.\n\n"
            f"**사용 예시:**\n"
            f"`@CTF-Bot @director challenges/dreamhack-2026/rsa-magic/ 풀어줘`\n\n"
            f"**주요 에이전트:**\n{agent_list}\n\n"
            f"전체 에이전트 목록: `/ctf-agents`",
            thread_ts=thread_ts,
        )


@app.command("/ctf-agents")
def handle_agents_command(ack, respond):
    """에이전트 목록 조회 슬래시 명령"""
    ack()

    sections = {
        "Director": ["director"],
        "Web Team": [k for k in AGENTS if k.startswith("web-")],
        "Pwn Team": [k for k in AGENTS if k.startswith("pwn-")],
        "Rev Team": [k for k in AGENTS if k.startswith("rev-")],
        "Forensics Team": [k for k in AGENTS if k.startswith("forensics-")],
        "Crypto Team": [k for k in AGENTS if k.startswith("crypto-")],
    }

    blocks = []
    for section, agents in sections.items():
        agent_text = "\n".join([f"• `@{a}` - {AGENTS[a]}" for a in agents])
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{section}*\n{agent_text}"},
            }
        )
        blocks.append({"type": "divider"})

    respond(blocks=blocks)


@app.command("/ctf-solve")
def handle_solve_command(ack, respond, command):
    """
    CTF 문제 풀이 슬래시 명령
    사용법: /ctf-solve <문제경로> [추가 설명]
    """
    ack()

    text = command.get("text", "").strip()
    if not text:
        respond("사용법: `/ctf-solve <문제경로> [추가 설명]`\n예: `/ctf-solve challenges/dreamhack-2026/rsa-magic/`")
        return

    respond(":robot_face: `@director`가 문제를 분석 중입니다...")

    response = call_claude_agent("director", text)

    if len(response) > 3000:
        respond(f"응답이 길어 요약합니다:\n\n{response[:2900]}...\n\n(전체 응답은 파일로 저장됨)")
    else:
        respond(response)


@app.event("message")
def handle_message(event, say):
    """DM 메시지 처리"""
    # 봇 자신의 메시지는 무시
    if event.get("bot_id"):
        return

    channel_type = event.get("channel_type")
    if channel_type == "im":  # DM
        text = event.get("text", "")
        request = parse_agent_request(text)

        if request:
            agent_type, prompt = request
            say(f":robot_face: `@{agent_type}` 에이전트가 분석 중입니다...")
            response = call_claude_agent(agent_type, prompt)
            say(response)
        else:
            # 기본적으로 director에게 전달
            say(":robot_face: `@director`에게 전달합니다...")
            response = call_claude_agent("director", text)
            say(response)


def main():
    """봇 실행"""
    # 환경변수 확인
    required_vars = ["SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"]
    missing = [v for v in required_vars if not os.environ.get(v)]
    if missing:
        print(f"필수 환경변수가 설정되지 않았습니다: {', '.join(missing)}")
        print("\n설정 방법:")
        print("  export SLACK_BOT_TOKEN='xoxb-...'")
        print("  export SLACK_APP_TOKEN='xapp-...'")
        return

    print("CTF Team Slack Bot 시작...")
    print(f"등록된 에이전트: {len(AGENTS)}개")

    handler = SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])
    handler.start()


if __name__ == "__main__":
    main()
