from __future__ import annotations

import json
import sys

from core.seed.llm_client import LLMCallError, LLMClient, extract_content
from scripts.verification_common import configure_llm_from_env, write_report


def main() -> int:
    config = configure_llm_from_env()
    client = LLMClient()
    messages = [
        {
            "role": "system",
            "content": [{"type": "text", "text": "You are a helpful assistant."}],
        },
        {
            "role": "user",
            "content": [{"type": "text", "text": "Reply with the single word: ready"}],
        },
    ]
    result: dict[str, object]
    try:
        payload, metadata = client.chat_with_metadata(messages, generated_by="verify_llm_endpoint")
        content = extract_content(payload)
        result = {
            "status": "pass",
            "http_status": metadata.llm_http_status,
            "response_received": metadata.llm_response_received,
            "real_call_verified": metadata.llm_real_call_verified,
            "content_parsed": bool(content.strip()),
            "content": content,
            "provider_model_echo": payload.get("model"),
            **metadata.to_dict(),
            **config,
        }
    except LLMCallError as exc:
        result = {
            "status": "fail",
            "content_parsed": False,
            "provider_model_echo": None,
            **exc.metadata.to_dict(),
            **config,
        }
    report_path = write_report("verify_llm_endpoint.json", result)
    print(json.dumps({**result, "report_path": str(report_path)}, indent=2))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
