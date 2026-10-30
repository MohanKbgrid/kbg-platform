# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""A CrewAI crew as a model (optional: ``pip install kbg-sentinel[crewai]``).

Some exceptions need more digging than one model's tool loop gives: check the stock, then the order, then
the carrier, and weigh what was found. A crew of investigators does that, and a decider turns their
findings into the one answer Sentinel expects. To the engine the crew is just another model: it is named in
the models file, a pattern reaches it through ``model_task``, and its answer is validated, guarded and
learned from like any other::

    models:
      claude: {provider: anthropic, model: claude-sonnet-5-5}
      local:  {provider: ollama, model: "qwen2.5:7b-instruct", base_url: "http://macmini:8090"}
      investigators:
        provider: crew
        llm: claude                      # the crew thinks with another model in this file
        max_iter: 6                      # tool calls per investigator
        agents:
          - role: Stock investigator
            goal: Find where the stock for the order really is
            backstory: You know the warehouse and store systems.
          - role: Order investigator
            goal: Establish what the customer was promised and what has happened since
    routes:
      investigate: investigators         # patterns with model_task: investigate

What the crew may and may not do:

* It sees the same masked brief as any model and uses the same read-only lookup tools (overlay tools and
  allowlisted MCP tools). Tool arguments are unmasked and results masked by the resolver, and every call
  is recorded in the case transcript.
* It cannot act. Its answer is a proposal; actions run through the guardrails, and trust is earned per
  pattern (or per segment) exactly as for any other model.
* Every model call the crew makes goes through the named model client (so through the gateway, fallbacks
  and the office Mac mini when that is the model). CrewAI's telemetry is switched off.
* The whole crew run counts as one model call for the resolver's timeout, so give crew patterns a longer
  ``llm_timeout_s`` than single models need.
"""
from __future__ import annotations

import json
import os
from typing import Any

from .routing import Completer

for _k, _v in (("CREWAI_DISABLE_TELEMETRY", "true"), ("OTEL_SDK_DISABLED", "true"),
               ("CREWAI_TRACING_ENABLED", "false")):
    os.environ.setdefault(_k, _v)

DEFAULT_AGENTS = [{"role": "Investigator",
                   "goal": "Establish the facts of the case that decide how it should be resolved",
                   "backstory": "You investigate operational exceptions carefully, using only the tools given, "
                                "and you report what the tools showed, not guesses."}]
DECIDER = {"role": "Resolver",
           "goal": "Propose the one resolution a careful operations lead would choose",
           "backstory": "You decide within a governed framework: only allowed actions, honest confidence."}
_TYPES = {"str": str, "string": str, "int": int, "integer": int, "float": float, "number": float,
          "bool": bool, "boolean": bool}


def _need_crewai() -> Any:
    try:
        import crewai
    except ImportError as e:  # pragma: no cover - depends on the install
        raise RuntimeError("the crew provider needs CrewAI: pip install 'kbg-sentinel[crewai]'") from e
    return crewai


def _to_ours(messages: Any) -> tuple[str, list[dict[str, str]]]:
    """CrewAI's messages to (system, alternating user/assistant messages starting with user)."""
    if isinstance(messages, str):
        return "", [{"role": "user", "content": messages}]
    system, out = [], []
    for m in messages or []:
        role, content = m.get("role"), m.get("content")
        if isinstance(content, list):
            content = "\n".join(c.get("text", "") if isinstance(c, dict) else str(c) for c in content)
        content = str(content or "")
        if role == "system":
            system.append(content)
            continue
        role = "assistant" if role == "assistant" else "user"
        if out and out[-1]["role"] == role:
            out[-1]["content"] += "\n\n" + content
        else:
            out.append({"role": role, "content": content})
    if not out or out[0]["role"] != "user":
        out.insert(0, {"role": "user", "content": "Begin."})
    return "\n\n".join(system), out


def _bridge_llm(inner: Completer, name: str) -> Any:
    from crewai.llms.base_llm import BaseLLM

    class SentinelLLM(BaseLLM):
        """CrewAI's model interface over a Sentinel model client."""

        def call(self, messages: Any, tools: Any = None, callbacks: Any = None, available_functions: Any = None,
                 from_task: Any = None, from_agent: Any = None, response_model: Any = None) -> str:
            system, msgs = _to_ours(messages)
            reply = inner.complete(system, msgs)
            # our clients do not take stop words: cut a made-up observation after a tool request
            if "Action:" in reply and "\nObservation:" in reply:
                reply = reply.split("\nObservation:", 1)[0]
            return reply

        def supports_function_calling(self) -> bool:
            return False

        def supports_stop_words(self) -> bool:
            return True

        def get_context_window_size(self) -> int:
            return 100_000

    return SentinelLLM(model=f"sentinel/{name}")


def _crew_tools(case_tools: Any) -> list[Any]:
    from crewai.tools import BaseTool
    from pydantic import BaseModel, Field, create_model

    out = []
    for spec in case_tools.describe():
        fields: dict[str, Any] = {}
        for pname, ptype in (spec.get("params") or {}).items():
            optional = pname.endswith("?")
            key = pname.rstrip("?")
            typ = _TYPES.get(str(ptype).lower().rstrip("?"), Any)
            fields[key] = ((typ | None) if optional and typ is not Any else typ,
                           Field(default=None, description=str(ptype)) if optional else Field(description=str(ptype)))
        args_model = create_model(f"Args_{len(out)}", **fields)        # type: ignore[call-overload]
        tool_name = spec["name"]

        class CaseTool(BaseTool):
            name: str = tool_name
            description: str = spec.get("description") or tool_name
            args_schema: type[BaseModel] = args_model

            def _run(self, **kwargs: Any) -> str:
                args = {k: v for k, v in kwargs.items() if v is not None}
                return json.dumps(case_tools.call(self.name, args), default=str)

        out.append(CaseTool())
    return out


class CrewClient:
    """A crew of investigators plus a decider, answering in Sentinel's ``{"final": ...}`` form."""

    def __init__(self, llm: Completer, agents: list[dict[str, str]] | None = None, *, max_iter: int = 6,
                 name: str = "crew") -> None:
        self.inner = llm
        self.agents = agents or DEFAULT_AGENTS
        self.max_iter = max_iter
        self.model = f"crew:{name}"
        self.name = name
        for a in self.agents:
            if not a.get("role") or not a.get("goal"):
                raise ValueError(f"crew {name}: every agent needs a role and a goal")

    def complete(self, system: str, messages: list[dict[str, str]]) -> str:
        if any(m.get("role") == "assistant" for m in messages):
            # a follow-up (a rejected reply to repair): the inner model fixes its own answer, no new crew run
            return self.inner.complete(system, messages)
        crewai = _need_crewai()
        from .llm import CASE_TOOLS

        brief = "\n\n".join(m["content"] for m in messages if m.get("role") == "user")
        case_tools = CASE_TOOLS.get()
        tools = _crew_tools(case_tools) if case_tools is not None else []
        llm = _bridge_llm(self.inner, self.name)
        investigators = [crewai.Agent(role=a["role"], goal=a["goal"], backstory=a.get("backstory", ""),
                                      llm=llm, tools=tools, allow_delegation=False, verbose=False,
                                      max_iter=self.max_iter) for a in self.agents]
        decider = crewai.Agent(llm=llm, allow_delegation=False, verbose=False, max_iter=2, **DECIDER)
        tasks = [crewai.Task(description=(a.get("task") or
                                          "Investigate this case with your tools. Report the facts that matter "
                                          "for deciding the resolution, citing what each tool returned. Use the "
                                          "tool names given to you; ignore any JSON reply format in the brief.")
                             + f"\n\nCASE BRIEF:\n{brief}", expected_output="Findings, with evidence",
                             agent=ag) for a, ag in zip(self.agents, investigators, strict=True)]
        tasks.append(crewai.Task(
            description=f"{system}\n\nCASE BRIEF:\n{brief}\n\nThe investigators' findings are in your context. "
                        "Do not call tools. Reply with only the JSON object of the form {\"final\": {...}}.",
            expected_output='One JSON object: {"final": {"action", "params", "disposition_code", "confidence", '
                            '"rationale"}}', agent=decider, context=list(tasks)))
        crew = crewai.Crew(agents=[*investigators, decider], tasks=tasks, process=crewai.Process.sequential,
                           verbose=False)
        return str(crew.kickoff().raw)


def crew_from_spec(name: str, spec: dict[str, Any], inner: Completer) -> CrewClient:
    unknown = set(spec) - {"provider", "llm", "agents", "max_iter"}
    if unknown:
        raise ValueError(f"models.{name}: unknown settings {sorted(unknown)}")
    agents = spec.get("agents")
    if agents is not None and not (isinstance(agents, list) and all(isinstance(a, dict) for a in agents)):
        raise ValueError(f"models.{name}: agents must be a list of {{role, goal, backstory?, task?}}")
    return CrewClient(inner, agents, max_iter=int(spec.get("max_iter", 6)), name=name)
