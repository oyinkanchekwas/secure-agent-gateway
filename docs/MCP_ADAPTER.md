# MCP host adapter

`MCPGatewayAdapter` maps authorised MCP tool calls to signed gateway requests. It targets the
`2026-07-28` MCP tool result format and has no transport dependency.

The class is an integration boundary for an MCP host or server implementation. It does not implement
JSON-RPC routing, Streamable HTTP, stdio framing, OAuth, discovery, or protocol negotiation.

## Host responsibilities

Before constructing an adapter, the host must:

- authenticate the caller and select a gateway key;
- mint an opaque session handle with a bounded lifetime;
- bind that handle to the credential through `PrincipalCredential.allowed_session_ids`;
- choose the tools visible to the caller; and
- retain approval receipts outside model-controlled content.

MCP no longer provides a transport session. The July 2026 specification treats state handles as
ordinary tool data and requires authorisation checks on each call. The adapter accepts a
`session_handle` from trusted host configuration and signs it into every gateway request. It never
accepts a replacement handle inside tool arguments.

A surrounding MCP server may expose its opaque handle as an ordinary argument, as the specification
describes. That server must validate the handle against the authenticated caller, remove it from the
registered tool arguments, and then select the corresponding adapter context.

## Tool discovery

`list_tools()` returns registered tools in deterministic order. Each input schema closes unknown
properties, carries required fields, and translates supported length, numeric, choice, and array
constraints from `FieldSpec`.

The result uses `cacheScope: private`, since visible tools may depend on caller authority. A host can
set the freshness period through `list_ttl_ms`.

## Tool calls

`call_tool()` creates a request identifier and nonce, signs the request, and submits it to the
gateway. Successful JSON output appears in both text and `structuredContent`, matching MCP guidance
for backwards compatibility.

Policy denials and adapter failures return tool errors. An undisclosed tool raises
`MCPProtocolError(-32602)`, which the surrounding server should convert to a JSON-RPC invalid-params
error.

An `execution_uncertain` result also returns a tool error, with wording that tells the host the
external action may have occurred. It is kept distinct from policy denial and adapter failure.

Pending approval also returns a tool error to prevent the model from assuming execution occurred.
The accompanying `MCPToolCallResult.gateway_result` gives trusted host code the request identifier
needed for its approval UI. That identifier is absent from `protocol_result`.

## Protocol version

The adapter emits `resultType: complete`, deterministic tool lists, `ttlMs`, and `cacheScope` as
defined by MCP `2026-07-28`. A server supporting older clients should negotiate its wire version and
translate the result at the transport boundary.
