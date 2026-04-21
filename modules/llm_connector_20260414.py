# [TRISHULA SEPTIP-v2 RATIFIED]
# [ANCHOR: 2026-04-14T05:43:16.951845+00:00]
# [BLOCK C/D RE-ANCHOR]

"""
LLM CONNECTOR — Dependency-Light LLM Interface
Part of the Trishula Security Janitor (Phase 2)

Standalone REST connector for LLM backends. Zero third-party AI SDK
dependencies — uses only stdlib `urllib` and `json`.

Supported backends:
    - local:  Ollama at localhost:11434 (default)
    - openai: OpenAI-compatible API (v1/chat/completions)
    - anthropic: Anthropic Messages API

Usage:
    connector = LLMConnector(mode="local", model="codellama:13b")
    response = connector.generate(system_prompt, user_prompt)

Environment variables:
    JANITOR_LLM_MODE       — "local" | "openai" | "anthropic"
    JANITOR_LLM_MODEL      — Model identifier
    JANITOR_LLM_ENDPOINT   — Custom endpoint URL
    OPENAI_API_KEY         — For openai mode
    ANTHROPIC_API_KEY      — For anthropic mode
    JANITOR_LLM_TIMEOUT    — Request timeout in seconds (default: 60)
    JANITOR_LLM_MAX_TOKENS — Max response tokens (default: 2048)
    JANITOR_LLM_TEMPERATURE — Temperature (default: 0.1)
"""

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger("Janitor.LLM")


# ─── Configuration ───────────────────────────────────────────────────────────

class LLMMode(Enum):
    LOCAL = "local"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


DEFAULT_ENDPOINTS = {
    LLMMode.LOCAL: "http://localhost:11434",
    LLMMode.OPENAI: "https://api.openai.com",
    LLMMode.ANTHROPIC: "https://api.anthropic.com",
}

DEFAULT_MODELS = {
    LLMMode.LOCAL: "phi3:mini",
    LLMMode.OPENAI: "gpt-4o",
    LLMMode.ANTHROPIC: "claude-sonnet-4-20250514",
}


@dataclass
class LLMConfig:
    """Runtime configuration for the LLM connector."""
    mode: LLMMode = LLMMode.LOCAL
    model: Optional[str] = None
    endpoint: Optional[str] = None
    api_key: Optional[str] = None
    timeout: int = 45
    max_tokens: int = 1024
    temperature: float = 0.1
    retries: int = 2
    retry_delay: float = 1.5

    def __post_init__(self):
        # Resolve defaults
        if self.model is None:
            self.model = DEFAULT_MODELS.get(self.mode, "phi3:mini")
        if self.endpoint is None:
            self.endpoint = DEFAULT_ENDPOINTS.get(self.mode, "http://localhost:11434")
        # Resolve API keys from environment
        if self.api_key is None:
            if self.mode == LLMMode.OPENAI:
                self.api_key = os.environ.get("OPENAI_API_KEY")
            elif self.mode == LLMMode.ANTHROPIC:
                self.api_key = os.environ.get("ANTHROPIC_API_KEY")

    @classmethod
    def from_env(cls) -> "LLMConfig":
        """Build config from environment variables."""
        mode_str = os.environ.get("JANITOR_LLM_MODE", "local").lower()
        try:
            mode = LLMMode(mode_str)
        except ValueError:
            logger.warning("Unknown LLM mode '%s', defaulting to local", mode_str)
            mode = LLMMode.LOCAL

        return cls(
            mode=mode,
            model=os.environ.get("JANITOR_LLM_MODEL"),
            endpoint=os.environ.get("JANITOR_LLM_ENDPOINT"),
            timeout=int(os.environ.get("JANITOR_LLM_TIMEOUT", "60")),
            max_tokens=int(os.environ.get("JANITOR_LLM_MAX_TOKENS", "2048")),
            temperature=float(os.environ.get("JANITOR_LLM_TEMPERATURE", "0.1")),
        )


# ─── Response Model ──────────────────────────────────────────────────────────

@dataclass
class LLMResponse:
    """Structured response from the LLM."""
    content: str
    model: str
    mode: str
    tokens_used: int = 0
    latency_ms: int = 0
    success: bool = True
    error: Optional[str] = None
    raw_response: dict = field(default_factory=dict)


# ─── Output Sanitizer ────────────────────────────────────────────────────────

class OutputSanitizer:
    """Strips markdown fences, explanations, and other noise from LLM output."""

    # Matches ```python ... ``` or ``` ... ``` blocks
    _fence_pattern = re.compile(
        r"```(?:python|py|javascript|js|typescript|ts|yaml|yml|json|bash|sh|sql)?\s*\n(.*?)```",
        re.DOTALL,
    )
    # Matches lines that are clearly explanation, not code
    _explanation_markers = [
        "here is", "here's", "the fix", "explanation", "note:",
        "i've", "i have", "this code", "the issue", "the problem",
        "changes made", "what changed", "summary",
    ]

    @classmethod
    def extract_code(cls, raw_output: str) -> str:
        """Extract clean code from LLM output, stripping markdown and explanations."""
        if not raw_output:
            return ""

        # Try to extract from code fences first
        fence_matches = cls._fence_pattern.findall(raw_output)
        if fence_matches:
            # Return the longest code block (most likely the actual fix)
            return max(fence_matches, key=len).strip()

        # If no fences, try to filter out explanation lines
        lines = raw_output.strip().splitlines()
        code_lines = []
        in_code = False

        for line in lines:
            stripped = line.strip().lower()

            # Skip empty lines at the start
            if not in_code and not stripped:
                continue

            # Skip obvious explanation lines
            if any(stripped.startswith(marker) for marker in cls._explanation_markers):
                continue

            # Once we see actual code-like content, start collecting
            if not in_code and (
                stripped.startswith(("import ", "from ", "def ", "class ", "#", "//"))
                or "=" in stripped
                or stripped.startswith(("if ", "for ", "while ", "try:", "return "))
            ):
                in_code = True

            if in_code:
                code_lines.append(line)

        if code_lines:
            return "\n".join(code_lines).strip()

        # Last resort: return the raw output stripped
        return raw_output.strip()

    @classmethod
    def extract_json(cls, raw_output: str) -> Optional[dict]:
        """Extract JSON from LLM output."""
        # Try direct parse
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError:
            pass

        # Try to find JSON in code fences
        json_pattern = re.compile(r"```(?:json)?\s*\n(.*?)```", re.DOTALL)
        matches = json_pattern.findall(raw_output)
        for match in matches:
            try:
                return json.loads(match.strip())
            except json.JSONDecodeError:
                continue

        # Try to find raw JSON object/array
        for start, end in [("{", "}"), ("[", "]")]:
            idx_start = raw_output.find(start)
            idx_end = raw_output.rfind(end)
            if idx_start != -1 and idx_end > idx_start:
                try:
                    return json.loads(raw_output[idx_start:idx_end + 1])
                except json.JSONDecodeError:
                    continue

        return None


# ─── LLM Connector ──────────────────────────────────────────────────────────

class LLMConnector:
    """
    Dependency-light LLM connector using only stdlib.

    Supports Ollama (local), OpenAI, and Anthropic backends.
    """

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig.from_env()
        self.logger = logging.getLogger("Janitor.LLM")
        self.sanitizer = OutputSanitizer()

        self.logger.info(
            "LLM Connector initialized: mode=%s, model=%s, endpoint=%s",
            self.config.mode.value, self.config.model, self.config.endpoint,
        )

    def generate(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        """Send a prompt to the LLM and return the response.

        Args:
            system_prompt: System-level instruction
            user_prompt: The user/task prompt

        Returns:
            LLMResponse with the generated content
        """
        self.logger.info("Generating LLM response (model=%s)...", self.config.model)
        self.logger.debug("System prompt: %s", system_prompt[:100])
        self.logger.debug("User prompt length: %d chars", len(user_prompt))

        for attempt in range(1, self.config.retries + 1):
            try:
                start_time = time.monotonic()

                if self.config.mode == LLMMode.LOCAL:
                    response = self._call_ollama(system_prompt, user_prompt)
                elif self.config.mode == LLMMode.OPENAI:
                    response = self._call_openai(system_prompt, user_prompt)
                elif self.config.mode == LLMMode.ANTHROPIC:
                    response = self._call_anthropic(system_prompt, user_prompt)
                else:
                    return LLMResponse(
                        content="", model=self.config.model or "",
                        mode=self.config.mode.value,
                        success=False, error=f"Unknown mode: {self.config.mode}",
                    )

                elapsed_ms = int((time.monotonic() - start_time) * 1000)
                response.latency_ms = elapsed_ms

                self.logger.info(
                    "LLM response received: %d chars, %dms, %d tokens",
                    len(response.content), elapsed_ms, response.tokens_used,
                )
                return response

            except Exception as e:
                self.logger.warning(
                    "LLM call attempt %d/%d failed: %s",
                    attempt, self.config.retries, e,
                )
                if attempt < self.config.retries:
                    time.sleep(self.config.retry_delay)

        return LLMResponse(
            content="", model=self.config.model or "",
            mode=self.config.mode.value,
            success=False,
            error=f"All {self.config.retries} attempts failed",
        )

    def generate_code(self, system_prompt: str, user_prompt: str) -> str:
        """Generate and sanitize code output from the LLM.

        Returns clean code string with markdown/explanations stripped.
        """
        response = self.generate(system_prompt, user_prompt)
        if not response.success:
            self.logger.error("LLM generation failed: %s", response.error)
            return ""

        clean_code = self.sanitizer.extract_code(response.content)
        self.logger.debug(
            "Sanitized output: %d chars → %d chars",
            len(response.content), len(clean_code),
        )
        return clean_code

    # ─── Backend Implementations ─────────────────────────────────────

    def _call_ollama(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        """Call local Ollama API."""
        url = f"{self.config.endpoint}/api/chat"
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
        }

        raw = self._http_post(url, payload)
        content = raw.get("message", {}).get("content", "")
        tokens = raw.get("eval_count", 0) + raw.get("prompt_eval_count", 0)

        return LLMResponse(
            content=content,
            model=self.config.model or "",
            mode="local",
            tokens_used=tokens,
            success=bool(content),
            raw_response=raw,
        )

    def _call_openai(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        """Call OpenAI-compatible chat completions API."""
        if not self.config.api_key:
            return LLMResponse(
                content="", model=self.config.model or "", mode="openai",
                success=False, error="OPENAI_API_KEY not set",
            )

        url = f"{self.config.endpoint}/v1/chat/completions"
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        }
        headers = {"Authorization": f"Bearer {self.config.api_key}"}

        raw = self._http_post(url, payload, extra_headers=headers)
        choices = raw.get("choices", [])
        content = choices[0]["message"]["content"] if choices else ""
        usage = raw.get("usage", {})
        tokens = usage.get("total_tokens", 0)

        return LLMResponse(
            content=content,
            model=self.config.model or "",
            mode="openai",
            tokens_used=tokens,
            success=bool(content),
            raw_response=raw,
        )

    def _call_anthropic(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        """Call Anthropic Messages API."""
        if not self.config.api_key:
            return LLMResponse(
                content="", model=self.config.model or "", mode="anthropic",
                success=False, error="ANTHROPIC_API_KEY not set",
            )

        url = f"{self.config.endpoint}/v1/messages"
        payload = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt},
            ],
        }
        headers = {
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
        }

        raw = self._http_post(url, payload, extra_headers=headers)
        content_blocks = raw.get("content", [])
        content = "".join(
            block.get("text", "") for block in content_blocks
            if block.get("type") == "text"
        )
        usage = raw.get("usage", {})
        tokens = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)

        return LLMResponse(
            content=content,
            model=self.config.model or "",
            mode="anthropic",
            tokens_used=tokens,
            success=bool(content),
            raw_response=raw,
        )

    # ─── HTTP Helper ─────────────────────────────────────────────────

    def _http_post(
        self,
        url: str,
        payload: dict,
        extra_headers: Optional[dict] = None,
    ) -> dict:
        """Execute an HTTP POST request using only stdlib."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore")
            self.logger.error("HTTP %d from %s: %s", e.code, url, body[:200])
            raise
        except urllib.error.URLError as e:
            self.logger.error("Connection failed to %s: %s", url, e.reason)
            raise
        except json.JSONDecodeError:
            self.logger.error("Invalid JSON response from %s", url)
            raise
