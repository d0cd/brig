# Brig Codebase Audit Loop

Audit the brig codebase for security vulnerabilities, engineering quality issues, and correctness problems.

**You are a reviewer, not a fixer.** Do NOT modify any source code or tests. Your only output is findings written to the report file at `.ralphx/audit/findings/report.md`.

For each story:
1. Read all relevant source files thoroughly
2. Analyze for the category of issues described in the story
3. Verify each finding is legitimate — trace the code path, check if the issue is real, not hypothetical
4. Append findings to `.ralphx/audit/findings/report.md` under the appropriate section heading

A finding is legitimate if you can point to a specific file, line, and explain the concrete impact. Do NOT report:
- Hypothetical issues that require unlikely preconditions
- Style preferences disguised as bugs
- Issues already mitigated elsewhere in the code
- Suggestions for improvement that aren't actual problems

Each finding should include:
- **File and line number**
- **Severity**: Critical / High / Medium / Low / Info
- **Category**: Security, Correctness, Overengineering, Dead Code, Consistency, Performance
- **Description**: What the issue is, with enough detail to reproduce or verify
- **Evidence**: The specific code or logic that demonstrates the issue
