#!/usr/bin/env python3
"""
oc2mapl - OpenClaw to MAPL Policy Translator

Converts OpenClaw configuration to MAPL policy format for SecureOpenClaw.
This is an offline utility for users migrating from legacy OpenClaw configs.

Usage:
    python oc2mapl.py                           # Use default ~/.openclaw/config.json
    python oc2mapl.py --config ./my-config.json # Use specific config
    python oc2mapl.py --output ./policies/      # Output to directory
    python oc2mapl.py --dry-run                 # Show what would be generated
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


# Tool categories (for documentation and recommendations)
TOOL_CATEGORIES = {
    # Observe level (read-only, no attestation)
    "read": "observe",
    "web_search": "observe",
    "web_fetch": "observe",
    "memory_search": "observe",
    "memory_get": "observe",
    "sessions_list": "observe",
    "sessions_history": "observe",
    "session_status": "observe",
    "agents_list": "observe",
    # Act level (mutations, requires action-mode attestation)
    "write": "act",
    "edit": "act",
    "apply_patch": "act",
    "exec": "act",
    "process": "act",
    "message": "act",
    "browser": "act",
    "canvas": "act",
    "image": "act",
    "tts": "act",
    "sessions_send": "act",
    "sessions_spawn": "act",
    "subagents": "act",
    # Transact level (automation, requires transact-mode attestation)
    "cron": "transact",
    "gateway": "transact",
    "nodes": "transact",
}

# OpenClaw profile to recommended role mapping
PROFILE_ROLES = {
    "minimal": "guest",      # observe only
    "coding": "user",        # observe + act with attestation
    "full": "owner",         # observe + act + transact
}

# SafeBin tools
SAFEBIN_TOOLS = ["jq", "grep", "cut", "sort", "uniq", "head", "tail", "tr", "wc"]


def load_openclaw_config(config_path: Path) -> Dict[str, Any]:
    """Load OpenClaw configuration file."""
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    with open(config_path) as f:
        return json.load(f)


def translate_profile_to_role(profile: str) -> str:
    """Translate OpenClaw profile to recommended MAPL role."""
    return PROFILE_ROLES.get(profile, "user")


def translate_tools_config(tools_config: Dict[str, Any]) -> Dict[str, Any]:
    """Translate OpenClaw tools config to MAPL policy elements."""
    result = {
        "allowed_tools": [],
        "denied_tools": [],
        "recommended_role": "user",  # default
        "needs_safebin_grants": False,
    }

    # Profile determines recommended role
    if "profile" in tools_config:
        result["recommended_role"] = translate_profile_to_role(tools_config["profile"])

    # Explicit allow/deny lists
    if "allow" in tools_config:
        result["allowed_tools"] = tools_config["allow"]

    if "deny" in tools_config:
        result["denied_tools"] = tools_config["deny"]

    # Exec config - check for safeBins usage
    if "exec" in tools_config:
        exec_config = tools_config["exec"]
        if "safeBins" in exec_config:
            result["needs_safebin_grants"] = True
            # Track which safebins are enabled
            result["enabled_safebins"] = exec_config["safeBins"]

    return result


def generate_user_policy(user_id: str, tools: List[str]) -> Dict[str, Any]:
    """Generate a user-specific policy from toolsBySender config."""
    return {
        "policy_id": f"user:{user_id}",
        "version": "1.0.0",
        "extends": "secureopenclaw",
        "description": f"User-specific policy for {user_id}",
        "resources": [f"tool:{t}" for t in tools],
    }


def generate_safebin_grant_policy(tool_name: str) -> Dict[str, Any]:
    """Generate a reusable attestation policy for a SafeBin tool."""
    return {
        "policy_id": f"grant:{tool_name}",
        "version": "1.0.0",
        "extends": f"tool:exec:{tool_name}",
        "description": f"Pre-approved attestation for {tool_name}",
        "attestations": [f"{tool_name}-grant"],
        "constraints": {
            "attestations": {
                f"{tool_name}-grant": {
                    "approval_criteria": "role:admin",
                    "time_to_live": 86400,
                    "one_time": False
                }
            }
        }
    }


def translate_config(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Translate full OpenClaw config to list of MAPL policies."""
    policies = []

    # Get tools config
    tools_config = config.get("tools", {})
    translated = translate_tools_config(tools_config)

    # Generate custom app policy if there are explicit allow/deny
    if translated["allowed_tools"] or translated["denied_tools"]:
        app_policy = {
            "policy_id": "app:custom",
            "version": "1.0.0",
            "description": "Custom policy from OpenClaw config",
            "extends": "secureopenclaw",
        }

        if translated["allowed_tools"]:
            app_policy["resources"] = [f"tool:{t}" for t in translated["allowed_tools"]]

        if translated["denied_tools"]:
            app_policy["denied_resources"] = [f"tool:{t}" for t in translated["denied_tools"]]

        policies.append(app_policy)

    # Generate SafeBin grant policies if safeBins were configured
    if translated.get("needs_safebin_grants"):
        enabled = translated.get("enabled_safebins", SAFEBIN_TOOLS)
        for tool in enabled:
            if tool in SAFEBIN_TOOLS:
                policies.append(generate_safebin_grant_policy(tool))

    # Handle per-sender policies (toolsBySender)
    tools_by_sender = config.get("toolsBySender", {})
    for sender_key, sender_config in tools_by_sender.items():
        # Extract user ID from sender key (e.g., "id:alice" -> "alice")
        if sender_key.startswith("id:"):
            user_id = sender_key[3:]
        else:
            user_id = sender_key

        allowed = sender_config.get("allow", [])
        if allowed:
            policies.append(generate_user_policy(user_id, allowed))

    return policies


def write_policies(policies: List[Dict[str, Any]], output_dir: Path) -> None:
    """Write policies to output directory."""
    output_dir.mkdir(parents=True, exist_ok=True)

    for policy in policies:
        policy_id = policy["policy_id"].replace(":", "_").replace("/", "_")
        output_path = output_dir / f"{policy_id}.json"

        with open(output_path, "w") as f:
            json.dump(policy, f, indent=2)

        print(f"  Created: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Convert OpenClaw config to MAPL policies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--config", "-c",
        type=Path,
        default=Path.home() / ".openclaw" / "config.json",
        help="Path to OpenClaw config (default: ~/.openclaw/config.json)"
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path.cwd() / "generated_policies",
        help="Output directory (default: ./generated_policies)"
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Show what would be generated without writing files"
    )

    args = parser.parse_args()

    print(f"oc2mapl - OpenClaw to MAPL Policy Translator")
    print(f"=" * 50)
    print(f"Config: {args.config}")
    print(f"Output: {args.output}")
    print()

    try:
        config = load_openclaw_config(args.config)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print()
        print("No OpenClaw config found. If you're starting fresh,")
        print("use the default SecureOpenClaw policies in policies/")
        sys.exit(1)

    # Get recommended role
    tools_config = config.get("tools", {})
    profile = tools_config.get("profile", "coding")
    recommended_role = translate_profile_to_role(profile)

    print(f"OpenClaw Profile: {profile}")
    print(f"Recommended Role: {recommended_role}")
    print()

    policies = translate_config(config)

    if not policies:
        print("No custom policies needed - using default SecureOpenClaw policies.")
        print()
        print("Default architecture:")
        print("  - Role-based access: guest / user / owner / admin")
        print("  - Attestations: action-mode (4h) / transact-mode (1h)")
        print("  - SafeBin attestations: jq-grant, grep-grant, etc. (one_time: false)")
        print()
        print(f"Based on your profile '{profile}', assign users the '{recommended_role}' role.")
        return

    print(f"Generated {len(policies)} custom policies:")
    print()

    if args.dry_run:
        for policy in policies:
            print(f"  {policy['policy_id']}:")
            print(f"    {json.dumps(policy, indent=4)}")
            print()
    else:
        write_policies(policies, args.output)
        print()
        print("Done! Load these policies via MACAW Console:")
        print("  1. Open console.macawsecurity.ai")
        print("  2. Go to Policies tab")
        print("  3. Import the generated JSON files")
        print()
        print(f"Based on your profile '{profile}', assign users the '{recommended_role}' role.")


if __name__ == "__main__":
    main()
