# Disclaimer

MCPHunter is a **security research tool** designed for defensive testing and security analysis of MCP (Model Context Protocol) tool definitions.

## Intended Use

- Security auditing of MCP server configurations
- Defensive research into prompt injection attack patterns
- Educational demonstration of adversarial machine learning in security
- Automated detection rule generation for MCP firewalls

## Restrictions

- **Do not** use generated attack payloads against systems without explicit authorization
- **Do not** deploy attack generation capabilities (HUNTER) against production MCP servers
- **Do not** use this tool for offensive operations, unauthorized penetration testing, or malicious purposes
- All attack payloads in `attacks/` and `benchmarks/` are synthetic, crafted for defensive testing

## Attack Payload Safety

- Attack payloads are stored as inert strings and never run as code
- The SHIELD pipeline scans payloads using regex, encoding detection, heuristics, and LLM classification only
- No dangerous code-running functions exist in the codebase
- All file writes are restricted to the project directory

## Responsible Disclosure

If you discover a genuine novel attack technique using MCPHunter, please follow responsible disclosure practices and report it to the affected MCP server maintainers before publishing.

## Legal

This software is provided "as is" under the MIT License. The authors are not responsible for misuse of this tool or any damages resulting from its use.
