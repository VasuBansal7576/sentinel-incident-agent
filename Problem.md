Hiring Hackathon
Autonomy, reliability, and production in agentic systems
Overview
This hackathon is the selection process for a single engineering role, and the selection rests on one artifact: an autonomous agent the applicant builds in five days against a brief that is identical for every candidate. The build itself is what we evaluate.

The reward is the position: a full-time, remote engineering role on the agentic systems that run production work at scale, offered to whichever candidate clears the bar set by the brief.

Applicants register through the form in section 05 and receive the assignment by email; the five-day window opens the moment that email arrives. At the end of the window, applicants reply on the same thread with the artifacts enumerated in section 03, all of which are read in full. The strongest submissions are invited to a thirty-minute review call, after which an offer may follow.

The brief
The assignment is to build a production-shaped autonomous agent from scratch, in a domain selected by the applicant. Five properties have to hold across the build; every other dimension, including language, framework, interface, execution model, context strategy, and evaluation harness, is left to the applicant.

Fifty or more tools across at least four namespaces
Tool selection is driven by the model rather than routed by hand, and the registry has to remain coherent at fifty tools rather than collapsing into a chain of fifty conditional dispatches.

Subagent orchestration
At least one tool spawns a subagent that executes in an isolated context, holds its own scoped tool set, and returns a structured result to the parent. The boundary has to be real context isolation; a function call relabelled as a subagent does not satisfy the requirement.

Long-horizon execution
The agent completes a task spanning at least 20 tool calls within a single session without loss of plan coherence, and the context-management strategy is expressed in the code itself rather than left implicit.

Production scaffolding
The build includes observability, retries with exponential backoff, rate limiting on external calls, typed error handling, an evaluation harness, and a test suite covering both unit and integration paths. The codebase is structured for deployment rather than for a notebook.

Composable tool inputs and outputs
At least one tool consumes the structured output of another, so that tools compose into chains rather than terminate at single calls.

Domains that fit the brief include repository automation, deep research, a devops or SRE agent, a personal-operations agent, and a coding agent. Applicants should select a domain that admits depth within five days of focused work.

A one-page MEMO.md is placed at the repository root. It documents the build itself, the components that were cut, the work additional time would have addressed, and one design decision the applicant would defend against an alternative an engineer might reasonably have made.

What to send back
The submission consists of four artifacts, returned to us by reply to the original assignment email.

A public GitHub repository
Both the source code and the commit history are read as part of the evaluation.

A three-to-five-minute video walkthrough
The video demonstrates the working build, walks the reviewer through the most substantive part of the code, and surfaces one moment in which the applicant and the model diverged.

Your prompts and the traces of your build sessions
The prompts and full session traces are submitted in the native export format of the tool that was used. As one example, Claude Code sessions are accepted as the JSONL files at ~/.claude/projects/<project>/, and Codex sessions are accepted via its own session export. Traces are submitted unedited, since the unmodified record is what we read for the applicant's reasoning under model use.

The MEMO.md
The MEMO may remain at the root of the repository alongside the code.

Terms
The build window is five focused days, measured from the moment the assignment email arrives, and is conducted in a stack and on a machine selected by the applicant.

Apply
Upon submission, the assignment is dispatched to the email address provided below within a few hours, and the five-day window opens the moment that email arrives.

Application received.
The assignment will be dispatched to the address provided within a few hours, and the five-day window opens the moment the email arrives.

At the close of the window, reply to that thread with the four artifacts enumerated in section 03: the GitHub repository, the video walkthrough, the prompts and traces, and the MEMO.md.