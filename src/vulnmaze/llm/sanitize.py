"""Output hardening for the LLM gap-filler.

Every model answer passes through these checks before an attacker can see it.
Each check returns *reasons*; any reason means the answer is rejected (the
gateway retries once, then falls back to a deterministic answer). Rejecting
is always safe; letting a bad answer through is not, so the checks err on
the side of rejecting.

1. Reasoning delimiters. Some models print their reasoning (<think>...</think>,
   <thought>...) before the answer, and that reasoning often quotes the
   system prompt [13]. Complete blocks are removed; an unclosed block
   rejects the answer.
2. Leakage, in the three tiers of [13]:
   S1a  verbatim prompt copy: any run of >= 7 consecutive words that also
        occurs in the instructions we wrote ("anchored" to our own text, so
        detection needs no judgement), or the per-deployment canary token.
   S1b  explicit self-disclosure: "as an AI", "language model", "honeypot"...
   S1c  implicit tells: chatty preambles ("Here is the output"), markdown.
3. Privilege denylist on *output*: the router keeps privilege commands away
   from the model, but a model could still invent privileged material
   (a shadow hash, a private key) or create files under sensitive paths.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from vulnmaze.router import is_sensitive_path

ANCHOR_WORDS = 7

# ---- 1. reasoning ------------------------------------------------------------

_REASONING_TAGS = ("think", "thinking", "thought", "reasoning", "reflection", "scratchpad", "analysis")
_BLOCK = re.compile(
    r"<\s*(" + "|".join(_REASONING_TAGS) + r")\s*>.*?<\s*/\s*\1\s*>", re.IGNORECASE | re.DOTALL
)
_OPEN = re.compile(r"<\s*(" + "|".join(_REASONING_TAGS) + r")\s*>", re.IGNORECASE)
_CLOSE_ONLY = re.compile(r"^.*?<\s*/\s*(" + "|".join(_REASONING_TAGS) + r")\s*>", re.IGNORECASE | re.DOTALL)
_SPECIAL_BLOCKS = [
    re.compile(r"<\|begin_of_thought\|>.*?<\|end_of_thought\|>", re.DOTALL),
    re.compile(r"\[THINK\].*?\[/THINK\]", re.DOTALL),
    re.compile(r"<\|channel\|>analysis<\|message\|>.*?<\|end\|>", re.DOTALL),
]


class Rejected(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def strip_reasoning(text: str) -> tuple[str, bool]:
    """Remove reasoning blocks. Returns (text, stripped?). Raises Rejected if
    a block is opened but never closed: we cannot tell where it ends."""
    original = text
    for pat in _SPECIAL_BLOCKS:
        text = pat.sub("", text)
    text = _BLOCK.sub("", text)
    # Some templates put the opening tag in the prompt, so only "</think>"
    # appears in the output: drop everything up to it.
    if not _OPEN.search(text):
        text = _CLOSE_ONLY.sub("", text, count=1)
    if _OPEN.search(text) or re.search(r"<\|begin_of_thought\|>|\[THINK\]", text):
        raise Rejected("reasoning_unclosed")
    return text, text != original


# ---- normalisation -------------------------------------------------------------

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_FENCE = re.compile(r"^```[A-Za-z0-9_+-]*\n(.*?)\n?```$", re.DOTALL)


def normalise(text: str, limit: int) -> str:
    """Terminal-safe text: no escape sequences or control bytes, \\n line
    endings, capped at `limit` characters on a line boundary."""
    text = _ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    text = _CTRL.sub("", text)
    if len(text) > limit:
        cut = text.rfind("\n", 0, limit)
        text = text[: cut + 1 if cut > 0 else limit]
    return text


def unwrap_fence(text: str) -> str:
    """A whole answer wrapped in one markdown code fence is unwrapped (a
    formatting habit, not a leak). A fence anywhere else is a tell."""
    m = _FENCE.match(text.strip())
    if not m:
        return text
    inner = m.group(1)
    return inner if not inner or inner.endswith("\n") else inner + "\n"


# ---- 2. leakage ----------------------------------------------------------------

_WORD = re.compile(r"[a-z0-9]+")

S1B_PATTERNS: list[tuple[str, re.Pattern]] = [
    (name, re.compile(pat, re.IGNORECASE))
    for name, pat in [
        ("as_an_ai", r"\bas an (?:ai|artificial intelligence|assistant|language model)\b"),
        ("i_am_ai", r"\bi(?: am|'m) (?:an? )?(?:ai|artificial intelligence|language model|assistant|chatbot|bot)\b"),
        ("language_model", r"\b(?:large )?language models?\b"),
        ("llm", r"\bllms?\b"),
        ("vendor", r"\b(?:chat ?gpt|openai|anthropic|claude|gemini|deepseek|mistral|qwen|llama ?\d|gpt-?\d)\b"),
        ("honeypot", r"\bhoney ?pots?\b|\bcowrie\b|\bvulnmaze\b|\bdecoy\b|\bdeception\b"),
        ("simulated", r"\bsimulat(?:ed|es|ing|ion|or)\b|\bemulat(?:ed|es|ing|ion|or)\b"),
        ("fake_env", r"\b(?:fake|virtual|mock|pretend) (?:shell|terminal|system|server|environment|output|machine)\b"),
        ("instructions", r"\bsystem prompt\b|\bmy (?:instructions|guidelines|rules)\b|\bthese instructions\b"),
        ("refusal", r"\bi (?:cannot|can't|can not|won't|will not|am unable to|'m unable to) "
                    r"(?:help|assist|comply|provide|do that|execute|run that)\b"),
        ("apology", r"\bi(?:'m| am) sorry\b|\bi apologi[sz]e\b"),
        ("roleplay", r"\brole-?play(?:ing)?\b"),
    ]
]

S1C_PREAMBLE = re.compile(
    r"^\s*(?:sure|certainly|of course|okay|ok|alright|here(?:'s| is| are)|below is|"
    r"the (?:output|result|response) (?:is|of|would)|this command|output\s*:|result\s*:|as requested)\b",
    re.IGNORECASE,
)
S1C_EXPLANATION = re.compile(r"^\s*(?:note|explanation|analysis|reasoning)\s*:", re.IGNORECASE | re.MULTILINE)
S1C_MARKDOWN = re.compile(r"```|\*\*[^*\n]+\*\*")


def _ngrams(words: list[str], n: int) -> set[tuple[str, ...]]:
    return {tuple(words[i : i + n]) for i in range(len(words) - n + 1)}


@dataclass
class LeakageDetector:
    """`corpus` is the text *we* wrote: the instruction block and persona
    role description. Not the persona facts, which are meant to appear."""

    corpus: Iterable[str]
    canary: str
    n: int = ANCHOR_WORDS

    def __post_init__(self) -> None:
        words: set[tuple[str, ...]] = set()
        for text in self.corpus:
            words |= _ngrams(_WORD.findall(text.lower()), self.n)
        self._anchors = words

    def check(self, text: str) -> list[str]:
        reasons: list[str] = []
        if self.canary and self.canary.lower() in text.lower():
            reasons.append("leak_s1a_canary")
        if _ngrams(_WORD.findall(text.lower()), self.n) & self._anchors:
            reasons.append("leak_s1a_prompt_copy")
        for name, pat in S1B_PATTERNS:
            if pat.search(text):
                reasons.append(f"leak_s1b_{name}")
        return reasons


def tells(stdout: str, stderr: str) -> list[str]:
    reasons: list[str] = []
    for label, text in (("stdout", stdout), ("stderr", stderr)):
        first = next((ln for ln in text.splitlines() if ln.strip()), "")
        if S1C_PREAMBLE.match(first):
            reasons.append(f"tell_s1c_preamble_{label}")
        if S1C_EXPLANATION.search(text):
            reasons.append(f"tell_s1c_explanation_{label}")
        if S1C_MARKDOWN.search(text):
            reasons.append(f"tell_s1c_markdown_{label}")
    return reasons


# ---- 3. privilege denylist on output ---------------------------------------------

DENYLIST: list[tuple[str, re.Pattern]] = [
    ("shadow_hash", re.compile(r"^[^:\s]+:\$(?:1|2[abxy]?|5|6|7|y|gy)\$[^:\s]*:", re.MULTILINE)),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("sudoers_rule", re.compile(r"^\s*[%\w.@-]+\s+ALL\s*=\s*\(", re.MULTILINE)),
]


def denylisted_content(text: str) -> list[str]:
    return [f"denylist_{name}" for name, pat in DENYLIST if pat.search(text)]


def denylisted_path(path: str, cwd: str, home: str) -> bool:
    return is_sensitive_path(path, cwd=cwd, home=home)
