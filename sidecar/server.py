"""
MACAW Sidecar Server for SecureOpenClaw

This FastAPI server bridges TypeScript (OpenClaw) and Python (MACAW).
All tool invocations flow through here for policy enforcement.

Flow:
1. OpenClaw (TS) calls POST /invoke with tool name and params
2. Sidecar calls macawClient.invoke_tool() for policy enforcement
3. If allowed, MACAW calls our registered handler
4. Handler calls back to TS callback server to execute actual tool
5. Result flows back through MACAW (signed, audited)
6. Sidecar returns result to OpenClaw

LLM Proxy Flow (SecureOpenAI/SecureAnthropic):
1. OpenClaw/pi-ai calls POST /openai/v1/chat/completions (or /anthropic/v1/messages)
2. Sidecar routes through SecureOpenAI/SecureAnthropic
3. Adapter routes through MACAW for policy check (model restrictions, token limits)
4. If allowed, adapter calls real provider API
5. Response streams back to caller

Usage:
    uvicorn server:app --host 127.0.0.1 --port 18798
"""

import os
import sys
import hmac
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, AsyncGenerator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel

# Import MACAW client (installed from macaw_client wheel)
try:
    from macaw_client import MACAWClient, PermissionDenied
    MACAW_AVAILABLE = True
except ImportError:
    MACAW_AVAILABLE = False
    MACAWClient = None
    PermissionDenied = Exception  # Fallback

# Import MACAW secure adapters for LLM proxy
try:
    from macaw_adapters.openai import SecureOpenAI
    from macaw_adapters.anthropic import SecureAnthropic
    ADAPTERS_AVAILABLE = True
except ImportError:
    ADAPTERS_AVAILABLE = False
    SecureOpenAI = None
    SecureAnthropic = None

# Configuration
CALLBACK_URL = os.getenv("MACAW_CALLBACK_URL", "http://127.0.0.1:18799")
HMAC_SECRET = os.getenv("MACAW_HMAC_SECRET", "secure-openclaw-dev-secret")
MACAW_APP_NAME = os.getenv("MACAW_APP_NAME", "secure-openclaw")

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("macaw-sidecar")

# Global state
macaw_client: Optional[Any] = None
registered_tools: Dict[str, bool] = {}

# LLM adapter instances (initialized if API keys available)
secure_openai: Optional[Any] = None
secure_anthropic: Optional[Any] = None


# Request/Response models
class Principal(BaseModel):
    userId: Optional[str] = None
    userName: Optional[str] = None
    role: Optional[str] = None
    channel: Optional[str] = None
    groupId: Optional[str] = None
    sessionKey: Optional[str] = None


class InvokeRequest(BaseModel):
    tool: str
    params: Dict[str, Any]
    principal: Optional[Principal] = None
    timeout: Optional[float] = 30.0
    skillName: Optional[str] = None  # Skill context for MAPL policy enforcement


class InvokeResponse(BaseModel):
    ok: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    message: Optional[str] = None
    policyMatched: Optional[str] = None
    auditId: Optional[str] = None


class RegisterToolsRequest(BaseModel):
    tools: List[str]


class RegisterToolsResponse(BaseModel):
    ok: bool
    registered: int


class AuditEvent(BaseModel):
    """Audit event matching MACAWClient.log_event() API."""
    event_type: str
    source: Optional[str] = None
    action: Optional[str] = None
    target: Optional[str] = None
    outcome: str = "success"  # "success", "failure", or "denied"
    signed: bool = False
    category: str = "custom"
    metadata: Optional[Dict[str, Any]] = None
    # Additional fields for SecureOpenClaw context
    principal: Optional[Principal] = None


class HealthResponse(BaseModel):
    status: str
    macawConnected: bool
    registeredTools: int
    openaiAvailable: bool = False
    anthropicAvailable: bool = False


def compute_hmac(data: Dict[str, Any]) -> str:
    """Compute HMAC signature for callback request."""
    payload = json.dumps(data, sort_keys=True)
    return hmac.new(
        HMAC_SECRET.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()


def create_callback_handler(tool_name: str):
    """
    Create a SYNCHRONOUS handler function that calls back to TypeScript.

    This handler is registered with MACAW and called when policy allows.
    MACAW expects synchronous handlers, so we use httpx sync client.
    """
    def handler(params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tool by calling back to TypeScript."""
        callback_url = f"{CALLBACK_URL}/execute/{tool_name}"

        # IMPORTANT: Use the same serialization for signing and sending
        # compute_hmac uses json.dumps(data, sort_keys=True)
        payload = json.dumps(params, sort_keys=True)
        signature = hmac.new(
            HMAC_SECRET.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        try:
            # Use synchronous client - MACAW handlers must be sync
            # Send the exact same payload that was signed
            response = httpx.post(
                callback_url,
                content=payload,
                headers={
                    "X-MACAW-Signature": signature,
                    "Content-Type": "application/json"
                },
                timeout=30.0
            )

            if response.status_code != 200:
                raise Exception(f"Callback failed: {response.status_code} {response.text}")

            result = response.json()
            if not result.get("ok", False):
                raise Exception(result.get("error", "Unknown error"))

            return result.get("result", {})

        except httpx.TimeoutException:
            raise Exception(f"Callback timeout for {tool_name}")
        except httpx.RequestError as e:
            raise Exception(f"Callback error: {str(e)}")

    return handler


def init_macaw_client() -> Optional[Any]:
    """Initialize MACAW client.

    MACAWClient auto-loads configuration from:
    1. $MACAW_HOME/.macaw/config.json
    2. ./.macaw/config.json
    3. ~/.macaw/config.json
    """
    global macaw_client

    if not MACAW_AVAILABLE:
        logger.error("MACAW client not installed. Run: pip install macaw_lib/macaw_client*.whl")
        return None

    # Check MACAW_HOME is set
    macaw_home = os.getenv("MACAW_HOME")
    if not macaw_home:
        logger.error("MACAW_HOME not set. Run install.sh first.")
        return None

    config_path = os.path.join(macaw_home, ".macaw", "config.json")
    if not os.path.exists(config_path):
        logger.error(f"MACAW config not found: {config_path}")
        return None

    try:
        # Create client - config auto-loaded from MACAW_HOME
        macaw_client = MACAWClient(app_name=MACAW_APP_NAME)
        logger.info(f"MACAWClient created: {MACAW_APP_NAME}")

        # Register with control plane (required before using client)
        if macaw_client.register():
            logger.info("Registered with MACAW control plane")
        else:
            logger.error("Failed to register with MACAW control plane")
            macaw_client = None
            return None

        return macaw_client

    except Exception as e:
        logger.error(f"Failed to initialize MACAW client: {e}")
        return None


def init_llm_adapters() -> None:
    """Initialize LLM adapters if API keys are available.

    Uses the same environment variables that OpenClaw uses:
    - OPENAI_API_KEY for OpenAI
    - ANTHROPIC_API_KEY for Anthropic
    """
    global secure_openai, secure_anthropic

    if not ADAPTERS_AVAILABLE:
        logger.warning("macaw_adapters not installed - LLM proxy disabled. "
                      "Install with: pip install -e /path/to/secureAI")
        return

    # Initialize OpenAI adapter
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        try:
            secure_openai = SecureOpenAI(
                app_name=MACAW_APP_NAME,
                api_key=openai_key
            )
            logger.info("SecureOpenAI adapter initialized")
        except Exception as e:
            logger.error(f"Failed to initialize SecureOpenAI: {e}")
    else:
        logger.info("OPENAI_API_KEY not set - OpenAI proxy disabled")

    # Initialize Anthropic adapter
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if anthropic_key:
        try:
            secure_anthropic = SecureAnthropic(
                app_name=MACAW_APP_NAME,
                api_key=anthropic_key
            )
            logger.info("SecureAnthropic adapter initialized")
        except Exception as e:
            logger.error(f"Failed to initialize SecureAnthropic: {e}")
    else:
        logger.info("ANTHROPIC_API_KEY not set - Anthropic proxy disabled")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    # Startup
    init_macaw_client()
    init_llm_adapters()

    if macaw_client:
        logger.info("SecureOpenClaw MACAW sidecar started (connected)")
    else:
        logger.warning("SecureOpenClaw MACAW sidecar started (NO MACAW - will fail)")

    adapters_status = []
    if secure_openai:
        adapters_status.append("OpenAI")
    if secure_anthropic:
        adapters_status.append("Anthropic")
    if adapters_status:
        logger.info(f"LLM adapters available: {', '.join(adapters_status)}")

    yield

    # Shutdown
    if macaw_client:
        try:
            macaw_client.unregister()
            logger.info("Unregistered from MACAW control plane")
        except Exception as e:
            logger.error(f"Error during unregister: {e}")
    logger.info("SecureOpenClaw MACAW sidecar stopped")


app = FastAPI(
    title="SecureOpenClaw MACAW Sidecar",
    description="Policy enforcement bridge for SecureOpenClaw",
    version="1.0.0",
    lifespan=lifespan
)


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy" if macaw_client else "mock",
        macawConnected=macaw_client is not None,
        registeredTools=len(registered_tools),
        openaiAvailable=secure_openai is not None,
        anthropicAvailable=secure_anthropic is not None
    )


@app.post("/register_tools", response_model=RegisterToolsResponse)
async def register_tools(request: RegisterToolsRequest):
    """Register tools with MACAW."""
    count = 0

    for tool_name in request.tools:
        if tool_name in registered_tools:
            continue

        handler = create_callback_handler(tool_name)

        if macaw_client:
            try:
                macaw_client.register_tool(tool_name, handler)
                registered_tools[tool_name] = True
                count += 1
                logger.debug(f"Registered tool: {tool_name}")
            except Exception as e:
                logger.error(f"Failed to register tool {tool_name}: {e}")
        else:
            # Mock mode - just track registration
            registered_tools[tool_name] = True
            count += 1

    logger.info(f"Registered {count} new tools (total: {len(registered_tools)})")
    return RegisterToolsResponse(ok=True, registered=len(registered_tools))


@app.post("/invoke", response_model=InvokeResponse)
async def invoke_tool(request: InvokeRequest):
    """
    Invoke a tool through MACAW for policy enforcement.

    This is the main entry point for all tool executions from OpenClaw.
    """
    tool_name = request.tool
    params = request.params
    principal = request.principal

    # Extract skill context from request or params
    skill_name = request.skillName or params.get("skillName") or params.get("skill_name")

    logger.debug(f"Invoke request: {tool_name}" + (f" [skill:{skill_name}]" if skill_name else ""))

    # Check tool is registered
    if tool_name not in registered_tools:
        return InvokeResponse(
            ok=False,
            error="tool_not_registered",
            message=f"Tool not registered: {tool_name}"
        )

    # Build security metadata for policy evaluation
    security_metadata = {}
    if principal:
        if principal.userId:
            security_metadata["principal_id"] = principal.userId
            security_metadata["user"] = principal.userId
        if principal.role:
            security_metadata["role"] = principal.role
        if principal.channel:
            security_metadata["channel"] = principal.channel
        if principal.sessionKey:
            security_metadata["session_key"] = principal.sessionKey

    if not macaw_client:
        # No MACAW client - fail closed
        logger.error(f"MACAW client not available - cannot invoke {tool_name}")
        return InvokeResponse(
            ok=False,
            error="macaw_unavailable",
            message="MACAW client not initialized. Check MACAW_HOME and config."
        )

    try:
        # Build intent_policy for skill context if provided
        # Uses per-invocation intent_policy parameter (thread-safe, no global state)
        intent_policy = None
        if skill_name:
            normalized_skill = skill_name.lower().replace("skill:", "")
            intent_policy = {"extends": f"skill:{normalized_skill}"}
            logger.debug(f"Using intent_policy: {intent_policy}")

        # Call MACAW for policy enforcement + execution
        # intent_policy is passed per-invocation, triggering extends resolution in PolicyResolver
        result = macaw_client.invoke_tool(
            tool_name=tool_name,
            parameters=params,
            target_agent=macaw_client.agent_id,
            intent_policy=intent_policy
        )

        return InvokeResponse(
            ok=True,
            result=result,
            auditId=result.get("_audit_id") if isinstance(result, dict) else None
        )

    except PermissionDenied as e:
        logger.warning(f"Policy denied: {tool_name} - {str(e)}")
        return InvokeResponse(
            ok=False,
            error="policy_denied",
            message=str(e)
        )
    except Exception as e:
        logger.error(f"Invoke failed: {tool_name} - {str(e)}")
        return InvokeResponse(
            ok=False,
            error="execution_failed",
            message=str(e)
        )


@app.post("/audit")
async def log_audit_event(event: AuditEvent):
    """Log an audit event to MACAW using MACAWClient.log_event() API."""
    # Build metadata with principal context if provided
    metadata = event.metadata or {}
    if event.principal:
        metadata["principal"] = {
            "userId": event.principal.userId,
            "role": event.principal.role,
            "channel": event.principal.channel,
            "sessionKey": event.principal.sessionKey,
        }

    if not macaw_client:
        logger.error("MACAW client not available - cannot log audit event")
        return {"ok": False, "error": "MACAW client not initialized"}

    try:
        success = macaw_client.log_event(
            event_type=event.event_type,
            source=event.source,
            action=event.action,
            target=event.target,
            outcome=event.outcome,
            signed=event.signed,
            category=event.category,
            metadata=metadata if metadata else None
        )
        return {"ok": success}
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}")
        return {"ok": False, "error": str(e)}


# ============================================================================
# LLM Proxy Endpoints (SecureOpenAI / SecureAnthropic)
# ============================================================================

class ChatCompletionRequest(BaseModel):
    """OpenAI chat completion request model."""
    model: str
    messages: List[Dict[str, Any]]
    stream: Optional[bool] = False
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    n: Optional[int] = None
    stop: Optional[Any] = None
    presence_penalty: Optional[float] = None
    frequency_penalty: Optional[float] = None
    user: Optional[str] = None
    tools: Optional[List[Dict[str, Any]]] = None
    tool_choice: Optional[Any] = None


async def stream_openai_response(params: dict) -> AsyncGenerator[str, None]:
    """Stream OpenAI response as Server-Sent Events."""
    try:
        # Call SecureOpenAI with streaming
        stream = secure_openai.chat.completions.create(**params)

        for chunk in stream:
            # Convert chunk to dict if it has model_dump
            if hasattr(chunk, 'model_dump'):
                data = chunk.model_dump()
            elif isinstance(chunk, dict):
                data = chunk
            else:
                data = {"content": str(chunk)}

            yield f"data: {json.dumps(data)}\n\n"

        yield "data: [DONE]\n\n"

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Streaming error: {error_msg}")
        yield f"data: {json.dumps({'error': error_msg})}\n\n"


@app.post("/openai/v1/chat/completions")
async def proxy_openai_chat(request: ChatCompletionRequest):
    """
    Proxy OpenAI chat completions through MACAW.

    This endpoint is OpenAI API compatible. Point pi-ai's baseUrl here
    to get MACAW policy enforcement on all LLM calls.
    """
    if not secure_openai:
        raise HTTPException(
            status_code=503,
            detail="OpenAI adapter not configured. Set OPENAI_API_KEY environment variable."
        )

    try:
        # Convert request to dict, excluding None values
        params = request.dict(exclude_none=True)

        logger.debug(f"OpenAI proxy request: model={params.get('model')}, "
                    f"stream={params.get('stream', False)}")

        if params.get('stream', False):
            # Streaming response
            return StreamingResponse(
                stream_openai_response(params),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                }
            )
        else:
            # Non-streaming response
            result = secure_openai.chat.completions.create(**params)

            # Convert to dict for JSON response
            if hasattr(result, 'model_dump'):
                return JSONResponse(result.model_dump())
            return JSONResponse(result)

    except Exception as e:
        error_msg = str(e)
        logger.error(f"OpenAI proxy error: {error_msg}")

        # Check if this is a policy denial
        if "denied" in error_msg.lower() or "policy" in error_msg.lower():
            raise HTTPException(status_code=403, detail=f"Policy denied: {error_msg}")

        raise HTTPException(status_code=500, detail=f"LLM error: {error_msg}")


class AnthropicMessageRequest(BaseModel):
    """Anthropic messages API request model."""
    model: str
    max_tokens: int
    messages: List[Dict[str, Any]]
    system: Optional[str] = None
    stream: Optional[bool] = False
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    top_k: Optional[int] = None
    stop_sequences: Optional[List[str]] = None
    tools: Optional[List[Dict[str, Any]]] = None
    tool_choice: Optional[Dict[str, Any]] = None


async def stream_anthropic_response(params: dict) -> AsyncGenerator[str, None]:
    """Stream Anthropic response as Server-Sent Events."""
    try:
        # Call SecureAnthropic with streaming
        stream = secure_anthropic.messages.create(**params)

        for chunk in stream:
            # Convert chunk to dict if it has model_dump
            if hasattr(chunk, 'model_dump'):
                data = chunk.model_dump()
            elif isinstance(chunk, dict):
                data = chunk
            else:
                data = {"content": str(chunk)}

            yield f"data: {json.dumps(data)}\n\n"

        yield "data: [DONE]\n\n"

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Anthropic streaming error: {error_msg}")
        yield f"data: {json.dumps({'error': error_msg})}\n\n"


@app.post("/anthropic/v1/messages")
async def proxy_anthropic_messages(request: AnthropicMessageRequest):
    """
    Proxy Anthropic messages API through MACAW.

    This endpoint is Anthropic API compatible. Point pi-ai's baseUrl here
    to get MACAW policy enforcement on all LLM calls.
    """
    if not secure_anthropic:
        raise HTTPException(
            status_code=503,
            detail="Anthropic adapter not configured. Set ANTHROPIC_API_KEY environment variable."
        )

    try:
        # Convert request to dict, excluding None values
        params = request.dict(exclude_none=True)

        logger.debug(f"Anthropic proxy request: model={params.get('model')}, "
                    f"stream={params.get('stream', False)}")

        if params.get('stream', False):
            # Streaming response
            return StreamingResponse(
                stream_anthropic_response(params),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                }
            )
        else:
            # Non-streaming response
            result = secure_anthropic.messages.create(**params)

            # Convert to dict for JSON response
            if hasattr(result, 'model_dump'):
                return JSONResponse(result.model_dump())
            return JSONResponse(result)

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Anthropic proxy error: {error_msg}")

        # Check if this is a policy denial
        if "denied" in error_msg.lower() or "policy" in error_msg.lower():
            raise HTTPException(status_code=403, detail=f"Policy denied: {error_msg}")

        raise HTTPException(status_code=500, detail=f"LLM error: {error_msg}")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("MACAW_SIDECAR_PORT", "18798"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
