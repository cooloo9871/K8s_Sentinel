#!/bin/bash
#
# Claude Code Hook — 對話紀錄腳本
#
# 將對話流（prompt / tool 呼叫 / 回覆）以 pretty-print JSON 寫入 log，
# 並把多行字串展開成真換行，方便人類閱讀。
#

set -euo pipefail

# ─── 前置檢查 ───────────────────────────────────────────────

INPUT=$(cat)

if ! command -v jq >/dev/null 2>&1; then
  echo "log-conversation hook: jq is required but not installed" >&2
  exit 0
fi

# ─── 解析基本欄位 & 設定 log 路徑 ──────────────────────────

SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // "unknown"')
EVENT=$(echo "$INPUT" | jq -r '.hook_event_name // "unknown"')

LOG_DIR="${CLAUDE_PROJECT_DIR}/.claude/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/conversation-${SESSION_ID}.log"

# ─── 共用函式 ──────────────────────────────────────────────

# 將 JSON 字串裡的 \n \t \" 還原成真字元後寫入 log
write_record() {
  local json="$1"

  echo "$json" \
    | jq '.' \
    | awk '{
        gsub(/\\n/, "\n")
        gsub(/\\t/, "\t")
        gsub(/\\"/, "\"")
        print
      }' >> "$LOG_FILE"

  echo ""                                        >> "$LOG_FILE"
  echo "----------------------------------------" >> "$LOG_FILE"
  echo ""                                        >> "$LOG_FILE"
}

# 從 stdin JSON 擷取工具名稱與輸入（多個事件共用）
parse_tool_fields() {
  TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // ""')
  TOOL_INPUT=$(echo "$INPUT" | jq -c '.tool_input // {}')
}

# ─── 依事件類型產生紀錄 ───────────────────────────────────

case "$EVENT" in

  UserPromptSubmit)
    PROMPT=$(echo "$INPUT" | jq -r '.prompt // ""')

    REC=$(jq -n \
      --arg event "$EVENT" \
      --arg prompt "$PROMPT" \
      '{event: $event, user_prompt: $prompt}')

    write_record "$REC"
    ;;

  PreToolUse)
    parse_tool_fields

    REC=$(jq -n \
      --arg event "$EVENT" \
      --arg tool "$TOOL_NAME" \
      --argjson input "$TOOL_INPUT" \
      '{event: $event, tool_name: $tool, tool_input: $input}')

    write_record "$REC"
    ;;

  PostToolUse)
    parse_tool_fields
    TOOL_RESPONSE=$(echo "$INPUT" | jq -c '.tool_response // null')

    REC=$(jq -n \
      --arg event "$EVENT" \
      --arg tool "$TOOL_NAME" \
      --argjson input "$TOOL_INPUT" \
      --argjson resp "$TOOL_RESPONSE" \
      '{event: $event, tool_name: $tool, tool_input: $input, tool_response: $resp}')

    write_record "$REC"
    ;;

  PostToolUseFailure)
    parse_tool_fields
    ERR_RESP=$(echo "$INPUT" | jq -c '{error: (.error // ""), is_interrupt: (.is_interrupt // false)}')

    REC=$(jq -n \
      --arg event "$EVENT" \
      --arg tool "$TOOL_NAME" \
      --argjson input "$TOOL_INPUT" \
      --argjson resp "$ERR_RESP" \
      '{event: $event, tool_name: $tool, tool_input: $input, tool_response: $resp}')

    write_record "$REC"
    ;;

  Stop)
    # transcript 寫檔可能還沒 flush，最多 retry 2 秒
    TRANSCRIPT=$(echo "$INPUT" | jq -r '.transcript_path // ""')
    ASSISTANT_TEXT=""

    if [[ -n "$TRANSCRIPT" && -f "$TRANSCRIPT" ]]; then
      for _ in $(seq 1 10); do
        ASSISTANT_TEXT=$(
          jq -rs '
            map(select(.type == "assistant"))
            | last
            | .message.content
            | map(select(.type == "text") | .text)
            | join("\n")
          ' "$TRANSCRIPT" 2>/dev/null || echo ""
        )
        [[ -n "$ASSISTANT_TEXT" ]] && break
        sleep 0.2
      done
    fi

    REC=$(jq -n \
      --arg event "$EVENT" \
      --arg reply "$ASSISTANT_TEXT" \
      '{event: $event, assistant_reply: $reply}')

    write_record "$REC"
    ;;

  *)
    ;;
esac

exit 0
