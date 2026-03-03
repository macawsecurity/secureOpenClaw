# SecureOpenClaw MAPL Policies

Defense-in-depth security policies for OpenClaw tools using MACAW Agentic Policy Language (MAPL).

## Architecture

### 5-Layer Defense Model

```
┌─────────────────────────────────────────────────────────┐
│ Layer 1: Base Denials (secureopenclaw.json)             │
│   - denied_resources: /etc/shadow, /etc/gshadow         │
│   - denied_parameters: rm -rf, fork bombs, etc.         │
│   → Absolute blocks, cannot be bypassed                 │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Role-Based Access (roles/*.json)               │
│   - guest: observe only, rate_limit=10                  │
│   - user: observe + act (with attestation)              │
│   - owner: observe + act + transact                     │
│   - admin: full access, policy management               │
│   → Dynamically resolved at runtime                     │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Attestations (action-mode, transact-mode)      │
│   - action-mode: 4h TTL, reusable                       │
│   - transact-mode: 1h TTL, one-time                     │
│   → su-like elevation, approved via Console             │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Parameter Validation (constraints.parameters)  │
│   - Type checking, required fields                      │
│   - max_length, min/max, allowed_values                 │
│   → Per-tool validation rules                           │
├─────────────────────────────────────────────────────────┤
│ Layer 5: Tool Implementation (sandboxing, isolation)    │
│   - SafeBin: sandboxed shell utilities                  │
│   - Per-tool grants for pre-approved access             │
│   → Tool-level security controls                        │
└─────────────────────────────────────────────────────────┘
```

## Directory Structure

```
policies/
├── secureopenclaw.json          # Base policy (Layer 1)
├── roles/
│   ├── role_guest.json          # Observe only
│   ├── role_user.json           # Observe + act with attestation
│   ├── role_owner.json          # + transact capabilities
│   └── role_admin.json          # Full access + policy management
└── tools/
    ├── tool_read.json           # Observe tools (no attestation)
    ├── tool_web_search.json
    ├── tool_web_fetch.json
    ├── tool_memory_*.json
    ├── tool_sessions_*.json
    ├── tool_agents_list.json
    ├── tool_write.json          # Act tools (action-mode)
    ├── tool_edit.json
    ├── tool_apply_patch.json
    ├── tool_exec.json           # Base for SafeBin
    ├── tool_process.json
    ├── tool_message.json
    ├── tool_browser.json
    ├── tool_canvas.json
    ├── tool_image.json
    ├── tool_tts.json
    ├── tool_sessions_send.json
    ├── tool_sessions_spawn.json
    ├── tool_subagents.json
    ├── tool_cron.json           # Transact tools (transact-mode)
    ├── tool_gateway.json
    ├── tool_nodes.json
    └── tool_exec_*.json         # SafeBin tools (grants)
```

## Tool Categories

### Observe (9 tools)
Read-only operations, no attestation required:
- `tool:read` - File reading
- `tool:web_search` - Web search
- `tool:web_fetch` - Fetch URLs
- `tool:memory_search` - Search memory
- `tool:memory_get` - Get memory items
- `tool:sessions_list` - List sessions
- `tool:sessions_history` - Session history
- `tool:session_status` - Session status
- `tool:agents_list` - List agents

### Act (13 tools)
Mutation operations, requires `action-mode` attestation (4h TTL):
- `tool:write` - File writing
- `tool:edit` - File editing
- `tool:apply_patch` - Apply patches
- `tool:exec` - Shell execution
- `tool:process` - Process management
- `tool:message` - Send messages
- `tool:browser` - Browser automation
- `tool:canvas` - Canvas drawing
- `tool:image` - Image generation
- `tool:tts` - Text-to-speech
- `tool:sessions_send` - Send to sessions
- `tool:sessions_spawn` - Spawn sessions
- `tool:subagents` - Manage subagents

### Transact (3 tools)
Infrastructure operations, requires `transact-mode` attestation (1h TTL, one-time):
- `tool:cron` - Scheduling/automation
- `tool:gateway` - API gateway management
- `tool:nodes` - Infrastructure nodes

### SafeBin (9 tools)
Sandboxed shell utilities, requires per-tool grants:
- `tool:exec:jq` - JSON processing (jq-grant)
- `tool:exec:grep` - Pattern search (grep-grant)
- `tool:exec:cut` - Field extraction (cut-grant)
- `tool:exec:sort` - Line sorting (sort-grant)
- `tool:exec:uniq` - Duplicate filtering (uniq-grant)
- `tool:exec:head` - First N lines (head-grant)
- `tool:exec:tail` - Last N lines (tail-grant)
- `tool:exec:tr` - Character translation (tr-grant)
- `tool:exec:wc` - Word/line count (wc-grant)

## Policy Inheritance

```
secureopenclaw (base)
    ├── role:guest
    ├── role:user
    ├── role:owner
    ├── role:admin
    ├── tool:read (observe)
    ├── tool:write (act)
    │   └── ...
    ├── tool:exec (act)
    │   ├── tool:exec:jq (safebin)
    │   ├── tool:exec:grep (safebin)
    │   └── ...
    └── tool:cron (transact)
```

## Attestation Flow

1. Agent requests tool requiring attestation
2. MACAW creates pending attestation request
3. User approves via Console (or grant pre-approves)
4. Attestation valid for TTL (action-mode: 4h, transact-mode: 1h)
5. `one_time: true` for transact operations

## Reusable Attestations (Grants)

SafeBin tools use reusable attestations (`one_time: false`) for pre-approved access:
- Admin approves attestation once
- Valid for 24h (`time_to_live: 86400`)
- Reusable within TTL (`one_time: false`)
- Example: `jq-grant` attestation enables `tool:exec:jq` usage

```json
{
  "attestations": ["jq-grant"],
  "constraints": {
    "attestations": {
      "jq-grant": {
        "approval_criteria": "role:admin",
        "time_to_live": 86400,
        "one_time": false
      }
    }
  }
}
```

## Loading Policies

1. Open [console.macawsecurity.ai](https://console.macawsecurity.ai)
2. Go to **Policies** tab
3. Import the JSON files from this directory

### Load Order
1. `secureopenclaw.json` (base)
2. Role policies from `roles/`
3. Tool policies from `tools/`

## Migrating from OpenClaw

If you have existing OpenClaw configuration, use the `oc2mapl` utility:

```bash
# Show what would be generated
python oc2mapl.py --dry-run

# Generate policies from your config
python oc2mapl.py --config ~/.openclaw/config.json --output ./my_policies/
```

## MAPL Semantics

- **Intersection**: Child policies narrow parent (cannot add resources)
- **denied_resources**: Absolute blocks (bypass-proof)
- **denied_parameters**: Pattern-based parameter blocking
- **extends**: Inherit and narrow from parent policy
- **Wildcards**: `*` single level, `**` recursive
