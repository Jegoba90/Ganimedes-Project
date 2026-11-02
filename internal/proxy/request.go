package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/Jegoba90/Ganimedes-Project/internal/audit"
	"github.com/Jegoba90/Ganimedes-Project/internal/jsoncheck"
	"github.com/Jegoba90/Ganimedes-Project/internal/policy"
)

// inspectRequest decodes only the envelope and the tools/call parameters. Raw
// maps deliberately replace struct decoding here: encoding/json matches struct
// fields case-insensitively and accepts the last duplicate, whereas another
// server can read a different method or tool from exactly the same wire bytes.
// An uncertain interpretation must never turn into permission (Art. 2.1).
func inspectRequest(line []byte, eng *policy.Engine, p *pending, appr Approver, log *audit.Logger, client io.Writer) bool {
	if !json.Valid(line) {
		return blockInvalidRequest(client, log, nil, line)
	}
	if isJSONArray(line) {
		return blockBatch(client, log, line)
	}
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(line, &msg); err != nil || msg == nil {
		return blockInvalidRequest(client, log, nil, line)
	}
	if jsoncheck.Validate(line) != nil || hasFieldAlias(msg, "jsonrpc", "id", "method", "params") {
		return blockInvalidRequest(client, log, nil, line)
	}
	if !version2(msg) {
		return blockInvalidRequest(client, log, msg["id"], line)
	}
	methodRaw, hasMethod := msg["method"]
	if !hasMethod {
		if !isResponse(msg) {
			return blockInvalidRequest(client, log, msg["id"], line)
		}
		return true // a client response to a server-initiated request
	}
	var method string
	if err := json.Unmarshal(methodRaw, &method); err != nil || method == "" {
		return blockInvalidRequest(client, log, msg["id"], line)
	}
	if _, exists := msg["result"]; exists {
		return blockInvalidRequest(client, log, msg["id"], line)
	}
	if _, exists := msg["error"]; exists {
		return blockInvalidRequest(client, log, msg["id"], line)
	}
	if method != "tools/call" {
		if params := bytes.TrimSpace(msg["params"]); len(params) > 0 && params[0] != '{' && params[0] != '[' {
			return blockInvalidRequest(client, log, msg["id"], line)
		}
		return rememberOtherRequest(client, log, p, msg["id"], line)
	}
	id := msg["id"]
	if !validID(id) {
		return blockInvalidRequest(client, log, nil, line)
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(msg["params"], &params); err != nil || params == nil || hasFieldAlias(params, "name", "arguments") {
		return blockInvalidRequest(client, log, id, line)
	}
	var tool string
	if err := json.Unmarshal(params["name"], &tool); err != nil || tool == "" {
		return blockInvalidRequest(client, log, id, line)
	}
	args := params["arguments"]
	if len(args) > 0 && bytes.TrimSpace(args)[0] != '{' {
		return blockInvalidRequest(client, log, id, line)
	}
	switch eng.Decide(tool) {
	case policy.Deny:
		return blockCall(client, log, id, args, tool, audit.DecisionDeny, denyMessage(tool))
	case policy.RequireApproval:
		return handleApproval(client, p, appr, log, id, tool, args)
	case policy.Allow:
		if p != nil {
			if err := p.remember(id, tool, args, audit.DecisionAllow); err != nil {
				return blockCall(client, log, id, args, tool, audit.DecisionDeny, pendingMessage(tool, err))
			}
		}
		return true
	default:
		return blockInvalidRequest(client, log, id, line)
	}
}

// rememberOtherRequest reserves ids even for requests whose contents are outside
// the audit's scope. Otherwise an initialize response sharing a tools/call id
// could complete the wrong audit record. Its empty tool is a marker telling the
// response side to release the reservation without recording a tool call.
func rememberOtherRequest(client io.Writer, log *audit.Logger, p *pending, id json.RawMessage, line []byte) bool {
	if len(id) == 0 {
		return true
	}
	if !validID(id) {
		return blockInvalidRequest(client, log, nil, line)
	}
	if p == nil {
		return true
	}
	if err := p.remember(id, "", nil, ""); err != nil {
		return blockCall(client, log, id, rawRequest(line), "(request)", audit.DecisionDeny, pendingMessage("(request)", err))
	}
	return true
}

// hasFieldAlias rejects differently cased spellings of fields that one server
// might treat as aliases and another as unrelated names. Exact spellings remain
// case-sensitive as required by JSON-RPC and MCP.
func hasFieldAlias(fields map[string]json.RawMessage, names ...string) bool {
	for key := range fields {
		for _, name := range names {
			if key != name && strings.EqualFold(key, name) {
				return true
			}
		}
	}
	return false
}

// validID permits the string and finite number ids used by JSON-RPC, keeping
// null, composite values and overflowing numbers out of the correlation map.
func validID(id json.RawMessage) bool {
	var value any
	if err := json.Unmarshal(id, &value); err != nil {
		return false
	}
	switch value.(type) {
	case string, float64:
		return true
	default:
		return false
	}
}

// rawRequest preserves even invalid UTF-8 and duplicate members as base64 in a
// valid JSON object. Treating the original bytes as a JSON argument would let
// canonicalization erase the ambiguity the refusal is meant to document.
func rawRequest(line []byte) json.RawMessage {
	return json.RawMessage(`{"raw_base64":"` + base64.StdEncoding.EncodeToString(line) + `"}`)
}

func blockInvalidRequest(client io.Writer, log *audit.Logger, id json.RawMessage, line []byte) bool {
	if !validID(id) {
		id = json.RawMessage("null")
	}
	return blockCall(client, log, id, rawRequest(line), "(invalid request)", audit.DecisionDeny,
		"blocked by Ganimedes: ambiguous or malformed JSON-RPC 2.0 message; tools/call requires an id and a nonempty tool name; arguments, when present, must be an object")
}

func version2(msg map[string]json.RawMessage) bool {
	var version string
	return json.Unmarshal(msg["jsonrpc"], &version) == nil && version == "2.0"
}

// isResponse distinguishes replies from server-initiated requests, which use a
// separate id namespace. An invalid response must not release a reservation:
// a later, real response would otherwise be lost or assigned to a newer call.
func isResponse(msg map[string]json.RawMessage) bool {
	_, hasMethod := msg["method"]
	_, hasResult := msg["result"]
	_, hasError := msg["error"]
	if !version2(msg) || hasMethod || hasResult == hasError || hasFieldAlias(msg, "jsonrpc", "id", "method", "result", "error") {
		return false
	}
	if !validID(msg["id"]) && (!hasError || !bytes.Equal(bytes.TrimSpace(msg["id"]), []byte("null"))) {
		return false
	}
	if !hasError {
		return true
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(msg["error"], &body) != nil || hasFieldAlias(body, "code", "message") {
		return false
	}
	var code float64
	message := bytes.TrimSpace(body["message"])
	return json.Unmarshal(body["code"], &code) == nil && !bytes.Equal(bytes.TrimSpace(body["code"]), []byte("null")) && code == math.Trunc(code) && len(message) > 0 && message[0] == '"'
}

// idKey compares decoded ids rather than their spelling on the wire. String
// escapes have no semantic meaning; numeric ids use the same IEEE-754 model
// as the audit format, so 1, 1.0 and 1e0 reserve one slot. Rounded numbers may
// conservatively collide, but cannot silently overwrite another pending call.
func idKey(id json.RawMessage) string {
	var text string
	if err := json.Unmarshal(id, &text); err == nil && !bytes.Equal(bytes.TrimSpace(id), []byte("null")) {
		return "s:" + text
	}
	number, err := strconv.ParseFloat(string(bytes.TrimSpace(id)), 64)
	if err == nil && !math.IsInf(number, 0) && !math.IsNaN(number) {
		if number == 0 {
			return "n:0" // negative zero and zero are the same numeric id
		}
		return "n:" + strconv.FormatFloat(number, 'g', -1, 64)
	}
	return "invalid:" + string(bytes.TrimSpace(id))
}
