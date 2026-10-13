// hark is a CLIProxyAPI plugin that fronts hark.com.
//
// A hark account is a browser session, not an OAuth grant: there is no refresh
// token and the session dies on a fixed date. Each account is therefore stored
// as its own credential file and treated as single-use. The plugin reports when
// it expires and how much of the quota is left, and asks the operator to log in
// again once it is gone.
package main

/*
#include <stdlib.h>
#include <stdint.h>
typedef struct { void* ptr; size_t len; } cliproxy_buffer;
typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);
typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;
typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);
typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;
static int hark_call_host(cliproxy_host_api* api, const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	return api->call(api->host_ctx, method, request, request_len, response);
}
static void hark_free_host_buffer(cliproxy_host_api* api, void* ptr, size_t len) {
	api->free_buffer(ptr, len);
}
extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	providerName = "hark"
	upstreamHost = "https://hark.com"
	tokenCookie  = "__Secure-hark.session_token"
	userAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"

	pathSignInSocial = "/api/auth/sign-in/social"
	pathGetSession   = "/api/auth/get-session"
	pathBilling      = "/api/billing/summary"
	pathSend         = "/api/messages/send"
	pathHistory      = "/api/messages/history"

	loginTTL    = 5 * time.Minute
	pollEvery   = 1500 * time.Millisecond
	replyWait   = 4 * time.Minute
	modelID     = "claude-opus-5-5"
	modelInLim  = 200000
	modelOutLim = 32000
)

func main() {}

// storedAuth is one hark account on disk. The session token never rotates, so
// the file is valid until ExpiresAt and then simply dead.
type storedAuth struct {
	Email     string `json:"email"`
	Name      string `json:"name,omitempty"`
	UserID    string `json:"userId,omitempty"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt,omitempty"`
	Timezone  string `json:"timezone,omitempty"`
}

func (s *storedAuth) expired() bool {
	t, ok := s.expiry()
	return ok && time.Now().After(t)
}

func (s *storedAuth) expiry() (time.Time, bool) {
	if s.ExpiresAt == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s.ExpiresAt)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func (s *storedAuth) identity() string {
	if s.Email != "" {
		return sanitize(s.Email)
	}
	sum := sha256.Sum256([]byte(s.Token))
	return hex.EncodeToString(sum[:])[:12]
}

func (s *storedAuth) fileName() string { return "hark-" + s.identity() + ".json" }

func (s *storedAuth) label() string {
	who := s.Email
	if s.Name != "" {
		who = fmt.Sprintf("%s <%s>", s.Name, s.Email)
	}
	if t, ok := s.expiry(); ok {
		days := int(time.Until(t).Hours() / 24)
		if days < 0 {
			return who + " · 已过期"
		}
		return fmt.Sprintf("%s · %d 天后到期", who, days)
	}
	return who
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 64 {
		out = out[:64]
	}
	if out == "" {
		return "account"
	}
	return out
}

func parseStored(raw []byte) (*storedAuth, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty credential")
	}
	var s storedAuth
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("credential parse: %w", err)
	}
	if s.Token == "" {
		return nil, fmt.Errorf("credential has no token")
	}
	if s.Timezone == "" {
		s.Timezone = "Asia/Taipei"
	}
	return &s, nil
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

var hostAPI *C.cliproxy_host_api

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	hostAPI = host
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var req []byte
	if request != nil && requestLen > 0 {
		req = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, err := handleMethod(C.GoString(method), req)
	if err != nil {
		writeResponse(response, errorEnvelope("plugin_error", err.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

func hostCall(method string, request []byte) ([]byte, error) {
	if hostAPI == nil || hostAPI.call == nil {
		return nil, fmt.Errorf("host API unavailable")
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var cReq unsafe.Pointer
	var reqLen C.size_t
	if len(request) > 0 {
		cReq = C.CBytes(request)
		defer C.free(cReq)
		reqLen = C.size_t(len(request))
	}
	var resp C.cliproxy_buffer
	rc := C.hark_call_host(hostAPI, cMethod, (*C.uint8_t)(cReq), reqLen, &resp)
	var out []byte
	if resp.ptr != nil && resp.len > 0 {
		out = C.GoBytes(resp.ptr, C.int(resp.len))
	}
	if resp.ptr != nil && hostAPI.free_buffer != nil {
		C.hark_free_host_buffer(hostAPI, resp.ptr, resp.len)
	}
	if rc != 0 {
		return out, fmt.Errorf("host call %s returned %d", method, int(rc))
	}
	return out, nil
}

func hostLog(level, message string) {
	if hostAPI == nil || hostAPI.call == nil {
		return
	}
	body, _ := json.Marshal(map[string]any{"level": level, "message": message})
	_, _ = hostCall(pluginabi.MethodHostLog, body)
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return okEnvelope(registration())
	case pluginabi.MethodPluginQuiesce:
		return okEnvelope(struct{}{})
	case pluginabi.MethodModelStatic:
		return okEnvelope(pluginapi.ModelResponse{Provider: providerName, Models: harkModels()})
	case pluginabi.MethodModelForAuth:
		return handleModelsForAuth(request)
	case pluginabi.MethodAuthIdentifier:
		return okEnvelope(map[string]string{"identifier": providerName})
	case pluginabi.MethodAuthParse:
		return handleParseAuth(request)
	case pluginabi.MethodAuthLoginStart, pluginabi.MethodAuthLoginPoll:
		// Accounts are added through the import page, not an OAuth button.
		return errorEnvelope("unsupported", "hark 账号通过「Hark 导入」页粘贴 token 添加"), nil
	case pluginabi.MethodAuthRefresh:
		return handleRefresh(request)
	case pluginabi.MethodExecutorIdentifier:
		return okEnvelope(map[string]string{"identifier": providerName})
	case pluginabi.MethodExecutorExecute:
		return handleExecute(request)
	case pluginabi.MethodExecutorExecuteStream:
		return handleExecuteStream(request)
	case pluginabi.MethodManagementRegister:
		return handleManagementRegister()
	case pluginabi.MethodManagementHandle:
		return handleManagement(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func registration() map[string]any {
	return map[string]any{
		"schema_version": pluginabi.SchemaVersion,
		"metadata": map[string]any{
			"Name":             providerName,
			"Version":          "0.1.0",
			"Author":           "hark-proxy",
			"GitHubRepository": "https://github.com/hark-proxy/hark",
		},
		"capabilities": map[string]any{
			"model_provider":          true,
			"auth_provider":           false,
			"executor":                true,
			"executor_model_scope":    "both",
			"executor_input_formats":  []string{"chat-completions"},
			"executor_output_formats": []string{"chat-completions"},
			"management_api":          true,
		},
	}
}

// modelAliases lists every id a client might send for this model. Claude Code
// asks for the bare id, but also resolves "opus" to a short name and sometimes
// appends a dated snapshot suffix. All of them hit the same hark account.
var modelAliases = []string{
	modelID,
	"claude-opus-5",
	"claude-opus-5-5-20250922",
}

func harkModels() []pluginapi.ModelInfo {
	out := make([]pluginapi.ModelInfo, 0, len(modelAliases))
	for _, id := range modelAliases {
		out = append(out, pluginapi.ModelInfo{
			ID:                         id,
			Object:                     "model",
			OwnedBy:                    providerName,
			DisplayName:                "Hark",
			Name:                       id,
			InputTokenLimit:            modelInLim,
			OutputTokenLimit:           modelOutLim,
			ContextLength:              modelInLim,
			MaxCompletionTokens:        modelOutLim,
			SupportedGenerationMethods: []string{"chat-completions"},
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

func handleModelsForAuth(raw []byte) ([]byte, error) {
	var req pluginapi.AuthModelRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	s, err := parseStored(req.StorageJSON)
	if err != nil || s.expired() {
		// An expired or unreadable account advertises nothing, so the host
		// routes around it instead of sending traffic that would 401.
		return okEnvelope(pluginapi.ModelResponse{Provider: providerName})
	}
	return okEnvelope(pluginapi.ModelResponse{Provider: providerName, Models: harkModels()})
}

func handleParseAuth(raw []byte) ([]byte, error) {
	var req pluginapi.AuthParseRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	s, err := parseStored(req.RawJSON)
	if err != nil {
		return okEnvelope(pluginapi.AuthParseResponse{Handled: false})
	}
	return okEnvelope(pluginapi.AuthParseResponse{Handled: true, Auth: toAuthData(s)})
}

func toAuthData(s *storedAuth) pluginapi.AuthData {
	storage, _ := json.Marshal(s)
	next := time.Now().Add(6 * time.Hour)
	if t, ok := s.expiry(); ok && t.Before(next) {
		next = t
	}
	return pluginapi.AuthData{
		Provider:         providerName,
		ID:               "hark-" + s.identity(),
		FileName:         s.fileName(),
		Label:            s.label(),
		StorageJSON:      storage,
		Attributes:       map[string]string{"email": s.Email},
		NextRefreshAfter: next,
	}
}

// loginFlow tracks one in-progress Google sign-in. hark redirects the browser
// back to a local callback once Google finishes, and that callback is where the
// session token arrives.
type loginFlow struct {
	expiresAt time.Time
	token     string
	errMsg    string
}

var loginFlows sync.Map // state -> *loginFlow

func handleLoginStart(raw []byte) ([]byte, error) {
	var req pluginapi.AuthLoginStartRequest
	_ = json.Unmarshal(raw, &req)

	// A token pasted into the panel skips the browser entirely.
	if tok := tokenFromMeta(req.Metadata); tok != "" {
		return finishLogin(tok)
	}

	// hark rejects any callbackURL outside its own domain, and the session token
	// lands in a cookie on hark.com, which this plugin can never read. The
	// Google URL is still useful: the operator signs in, then copies the
	// cookie back through the import page.
	state := randomState()
	body, _ := json.Marshal(map[string]any{
		"provider":        "google",
		"callbackURL":     "https://hark.com/chat",
		"disableRedirect": true,
	})
	httpReq, _ := http.NewRequest(http.MethodPost, upstreamHost+pathSignInSocial, bytes.NewReader(body))
	browserHeaders(httpReq)
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("start google login: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var started struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(respBody, &started) != nil || started.URL == "" {
		return nil, fmt.Errorf("hark did not return a google login url (HTTP %d): %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	loginFlows.Store(state, &loginFlow{expiresAt: time.Now().Add(loginTTL)})
	hostLog("info", "hark: login started")
	return okEnvelope(pluginapi.AuthLoginStartResponse{
		Provider:  providerName,
		URL:       started.URL,
		State:     state,
		ExpiresAt: time.Now().Add(loginTTL),
	})
}

// tokenFromMeta finds a session token the operator pasted into the login form.
func tokenFromMeta(meta map[string]any) string {
	for _, key := range []string{"token", "session_token", "cookie"} {
		v, _ := meta[key].(string)
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if i := strings.Index(v, tokenCookie+"="); i >= 0 {
			v = v[i+len(tokenCookie)+1:]
		}
		if i := strings.IndexAny(v, "; \n"); i >= 0 {
			v = v[:i]
		}
		return strings.TrimSpace(v)
	}
	return ""
}

// finishLogin validates a pasted token and completes the flow immediately.
func finishLogin(token string) ([]byte, error) {
	s, err := accountFromToken(token)
	if err != nil {
		return nil, err
	}
	hostLog("info", "hark: account added "+s.Email)
	state := randomState()
	loginFlows.Store(state, &loginFlow{expiresAt: time.Now().Add(time.Minute), token: token})
	return okEnvelope(pluginapi.AuthLoginStartResponse{
		Provider:  providerName,
		URL:       "",
		State:     state,
		ExpiresAt: time.Now().Add(time.Minute),
	})
}

func callbackBase(hostBase string) string {
	if strings.HasPrefix(hostBase, "http") {
		return strings.TrimRight(hostBase, "/")
	}
	return "http://127.0.0.1:8317"
}

func handleLoginPoll(raw []byte) ([]byte, error) {
	var req pluginapi.AuthLoginPollRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	v, ok := loginFlows.Load(req.State)
	if !ok {
		return okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: "登录已过期，请重新发起"})
	}
	flow := v.(*loginFlow)

	if flow.token == "" {
		if time.Now().After(flow.expiresAt) {
			loginFlows.Delete(req.State)
			return okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: "登录超时"})
		}
		return okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusPending, Message: "等待 Google 登录完成"})
	}

	s, err := accountFromToken(flow.token)
	loginFlows.Delete(req.State)
	if err != nil {
		return okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: err.Error()})
	}
	hostLog("info", "hark: account added "+s.Email)
	return okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusSuccess, Auth: toAuthData(s)})
}

// handleRefresh cannot extend a hark session — there is no refresh token. It
// re-reads the account so the label and expiry stay current, and reports the
// account as-is. Once expired, model.for_auth drops it from rotation.
func handleRefresh(raw []byte) ([]byte, error) {
	var req pluginapi.AuthRefreshRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	s, err := parseStored(req.StorageJSON)
	if err != nil {
		return nil, err
	}
	if fresh, err := accountFromToken(s.Token); err == nil {
		s = fresh
	} else if s.expired() {
		hostLog("warn", "hark: "+s.Email+" session expired, log in again")
	}
	return okEnvelope(map[string]any{"auth": toAuthData(s)})
}

func accountFromToken(token string) (*storedAuth, error) {
	body, status, err := harkGET(token, pathGetSession, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || len(body) == 0 || string(body) == "null" {
		return nil, fmt.Errorf("hark 不认这个会话 (HTTP %d)", status)
	}
	var data struct {
		User struct {
			Email string `json:"email"`
			Name  string `json:"name"`
			ID    string `json:"id"`
		} `json:"user"`
		Session struct {
			ExpiresAt string `json:"expiresAt"`
		} `json:"session"`
	}
	if err := json.Unmarshal(body, &data); err != nil || data.User.Email == "" {
		return nil, fmt.Errorf("会话响应里没有账号信息")
	}
	return &storedAuth{
		Email:     data.User.Email,
		Name:      data.User.Name,
		UserID:    data.User.ID,
		Token:     token,
		ExpiresAt: data.Session.ExpiresAt,
		Timezone:  "Asia/Taipei",
	}, nil
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

type chatMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

// transcript renders the whole conversation into one message.
//
// The memory lives in the client's request, not on hark. CPA may serve two
// consecutive turns of the same conversation from different accounts once one
// runs out of quota, and neither account would hold the full history, so each
// turn is sent self-contained. A fresh hark conversation is used every time,
// which also keeps one client's history from ever leaking into another's.
func transcript(payload []byte) (string, error) {
	var req struct {
		Messages []chatMessage `json:"messages"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return "", fmt.Errorf("bad request body: %w", err)
	}
	var b strings.Builder
	for _, m := range req.Messages {
		text := messageText(m.Content)
		if text == "" {
			continue
		}
		role := strings.ToLower(strings.TrimSpace(m.Role))
		if role == "" {
			role = "user"
		}
		fmt.Fprintf(&b, "[%s]\n%s\n\n", role, text)
	}
	if b.Len() == 0 {
		return "", fmt.Errorf("no message content")
	}
	b.WriteString("Continue this conversation. Reply only to the last [user] message, " +
		"using the earlier messages as context. Do not mention these role labels or repeat the transcript.")
	return b.String(), nil
}

func handleExecute(raw []byte) ([]byte, error) {
	var req pluginapi.ExecutorRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	s, err := parseStored(req.StorageJSON)
	if err != nil {
		return nil, err
	}
	if s.expired() {
		return nil, fmt.Errorf("%s 的会话已于 %s 到期，请重新登录", s.Email, s.ExpiresAt)
	}
	body := req.Payload
	if len(body) == 0 {
		body = req.OriginalRequest
	}
	text, err := transcript(body)
	if err != nil {
		return nil, err
	}
	answer, err := completeFresh(s, text)
	if err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(completion(req.Model, answer))
	return okEnvelope(pluginapi.ExecutorResponse{Payload: payload})
}

func handleExecuteStream(raw []byte) ([]byte, error) {
	var req struct {
		pluginapi.ExecutorRequest
		StreamID string `json:"stream_id,omitempty"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	s, err := parseStored(req.StorageJSON)
	if err != nil {
		return nil, err
	}
	body := req.Payload
	if len(body) == 0 {
		body = req.OriginalRequest
	}
	text, err := transcript(body)
	if err != nil {
		return nil, err
	}

	headers := http.Header{}
	headers.Set("Content-Type", "text/event-stream")
	headers.Set("Cache-Control", "no-cache")

	// hark answers in one shot, so the stream is the finished text split into
	// chunks. With an async stream id those chunks go out through the host as
	// they are cut; otherwise they are returned inline.
	if req.StreamID != "" {
		go func() {
			answer, err := completeFresh(s, text)
			if err != nil {
				emitError(req.StreamID, err.Error())
				streamClose(req.StreamID)
				return
			}
			for _, chunk := range sseChunks(req.Model, answer) {
				if err := streamEmit(req.StreamID, []byte(chunk)); err != nil {
					break
				}
			}
			streamClose(req.StreamID)
		}()
		return okEnvelope(map[string]any{"headers": headers})
	}

	answer, err := completeFresh(s, text)
	if err != nil {
		return nil, err
	}
	var chunks []map[string]any
	for _, c := range sseChunks(req.Model, answer) {
		chunks = append(chunks, map[string]any{"payload": []byte(c)})
	}
	return okEnvelope(map[string]any{"headers": headers, "chunks": chunks})
}

// completeFresh runs one self-contained turn in a throwaway conversation and
// deletes it afterwards. hark has no API for emptying a conversation, only for
// deleting one, so each turn gets its own. The transcript carries the context,
// which means the reply does not depend on which account handled the turn.
func completeFresh(s *storedAuth, text string) (string, error) {
	convID, err := createConversation(s, "turn")
	if err != nil {
		return "", err
	}
	defer deleteConversation(s, convID)
	sent, err := sendMessage(s, convID, text)
	if err != nil {
		return "", err
	}
	return awaitReply(s, convID, sent)
}

func deleteConversation(s *storedAuth, convID string) {
	if _, status, err := harkDo(s.Token, http.MethodDelete, "/api/conversations/"+convID, nil, nil); err != nil || status >= 300 {
		hostLog("warn", fmt.Sprintf("hark: delete %s failed (HTTP %d)", convID, status))
	}
}

// conversationFor returns the hark conversation a request belongs to.
//
// Every proxied request used to land in the account's single main chat, so two
// clients sharing an account would read each other's history. A request can
// name its own conversation three ways, checked in order: an explicit
// "conversation" field, the OpenAI "user" field, or the first system message.
// Each distinct key gets its own hark conversation, created once and reused, so
// projects and people stay apart. Nothing set falls back to the main chat.
func conversationFor(s *storedAuth, payload []byte) (string, error) {
	key := conversationKey(payload)
	if key == "" {
		return mainConversation(s)
	}
	if id, ok := cachedConversation(s, key); ok {
		return id, nil
	}
	id, err := createConversation(s, key)
	if err != nil {
		return "", err
	}
	storeConversation(s, key, id)
	hostLog("info", "hark: new conversation for "+s.Email+" key="+truncate(key, 60))
	return id, nil
}

func conversationKey(payload []byte) string {
	var req struct {
		Conversation string        `json:"conversation"`
		User         string        `json:"user"`
		Messages     []chatMessage `json:"messages"`
	}
	if json.Unmarshal(payload, &req) != nil {
		return ""
	}
	if k := strings.TrimSpace(req.Conversation); k != "" {
		return "c:" + k
	}
	if k := strings.TrimSpace(req.User); k != "" {
		return "u:" + k
	}
	for _, m := range req.Messages {
		if strings.EqualFold(m.Role, "system") {
			if text := messageText(m.Content); text != "" {
				sum := sha256.Sum256([]byte(text))
				return "s:" + hex.EncodeToString(sum[:8])
			}
		}
	}
	return ""
}

func messageText(content any) string {
	switch c := content.(type) {
	case string:
		return strings.TrimSpace(c)
	default:
		b, _ := json.Marshal(c)
		return strings.TrimSpace(string(b))
	}
}

func mainConversation(s *storedAuth) (string, error) {
	q := url.Values{"timezone": {s.Timezone}}
	body, status, err := harkGET(s.Token, "/api/conversations/main", q)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("conversations/main HTTP %d", status)
	}
	var data struct {
		ConversationID string `json:"conversationId"`
	}
	if err := json.Unmarshal(body, &data); err != nil || data.ConversationID == "" {
		return "", fmt.Errorf("no main conversation")
	}
	return data.ConversationID, nil
}

func createConversation(s *storedAuth, key string) (string, error) {
	title := key
	if len(title) > 80 {
		title = title[:80]
	}
	payload, _ := json.Marshal(map[string]any{"title": "proxy " + title, "autoTitle": false})
	body, status, err := harkPOST(s.Token, "/api/conversations", nil, payload)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("create conversation HTTP %d: %s", status, truncate(string(body), 200))
	}
	var data struct {
		ConversationID string `json:"conversationId"`
	}
	if err := json.Unmarshal(body, &data); err != nil || data.ConversationID == "" {
		return "", fmt.Errorf("create conversation returned no id")
	}
	return data.ConversationID, nil
}

// convCache remembers which hark conversation serves a given key. It lives in
// the plugin process; a restart just creates fresh conversations, which is safe
// because proxy traffic has no history worth keeping.
var convCache sync.Map

func convCacheKey(s *storedAuth, key string) string { return s.identity() + "|" + key }

func cachedConversation(s *storedAuth, key string) (string, bool) {
	v, ok := convCache.Load(convCacheKey(s, key))
	if !ok {
		return "", false
	}
	return v.(string), true
}

func storeConversation(s *storedAuth, key, id string) {
	convCache.Store(convCacheKey(s, key), id)
}

func sendMessage(s *storedAuth, convID, text string) (string, error) {
	payload, _ := json.Marshal(map[string]string{
		"timezone":          s.Timezone,
		"conversationId":    convID,
		"message":           text,
		"idempotencyKey":    newUUID(),
		"responseMessageId": newUUID(),
	})
	q := url.Values{"cid": {convID}}
	body, status, err := harkPOST(s.Token, pathSend, q, payload)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("messages/send HTTP %d: %s", status, truncate(string(body), 300))
	}
	var data struct {
		MessageID string `json:"messageId"`
	}
	if err := json.Unmarshal(body, &data); err != nil || data.MessageID == "" {
		return "", fmt.Errorf("send returned no messageId")
	}
	return data.MessageID, nil
}

func awaitReply(s *storedAuth, convID, messageID string) (string, error) {
	deadline := time.Now().Add(replyWait)
	q := url.Values{"conversationId": {convID}, "v": {"2"}}
	for time.Now().Before(deadline) {
		body, status, err := harkGET(s.Token, pathHistory, q)
		if err == nil && status == http.StatusOK {
			if text := replyText(body, messageID); text != "" {
				return text, nil
			}
		}
		time.Sleep(pollEvery)
	}
	return "", fmt.Errorf("hark 接受了消息但在 %s 内没有回复", replyWait)
}

func replyText(body []byte, messageID string) string {
	var data struct {
		Messages map[string]struct {
			Role                 string `json:"role"`
			Content              string `json:"content"`
			TriggeredByMessageID string `json:"triggeredByMessageId"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &data) != nil {
		return ""
	}
	for _, m := range data.Messages {
		if m.Role == "assistant" && m.TriggeredByMessageID == messageID && strings.TrimSpace(m.Content) != "" {
			return m.Content
		}
	}
	return ""
}

func completion(model, text string) map[string]any {
	return map[string]any{
		"id":      "chatcmpl-" + newUUID()[:8],
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   firstNonEmpty(model, modelID),
		"choices": []any{map[string]any{
			"index":         0,
			"message":       map[string]any{"role": "assistant", "content": text},
			"finish_reason": "stop",
		}},
	}
}

func sseChunks(model, text string) []string {
	id := "chatcmpl-" + newUUID()[:8]
	created := time.Now().Unix()
	mk := func(delta map[string]any, finish any) string {
		b, _ := json.Marshal(map[string]any{
			"id": id, "object": "chat.completion.chunk", "created": created,
			"model":   firstNonEmpty(model, modelID),
			"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
		})
		return "data: " + string(b)
	}
	out := []string{mk(map[string]any{"role": "assistant"}, nil)}
	for _, piece := range splitRunes(text, 200) {
		out = append(out, mk(map[string]any{"content": piece}, nil))
	}
	out = append(out, mk(map[string]any{}, "stop"), "data: [DONE]")
	return out
}

func streamEmit(streamID string, payload []byte) error {
	body, _ := json.Marshal(map[string]any{"stream_id": streamID, "payload": payload})
	_, err := hostCall(pluginabi.MethodHostStreamEmit, body)
	return err
}

func emitError(streamID, message string) {
	b, _ := json.Marshal(map[string]any{"error": map[string]any{"message": message}})
	_ = streamEmit(streamID, b)
}

func streamClose(streamID string) {
	body, _ := json.Marshal(map[string]any{"stream_id": streamID})
	_, _ = hostCall(pluginabi.MethodHostStreamClose, body)
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

type usage struct {
	Email        string  `json:"email"`
	Name         string  `json:"name"`
	ExpiresAt    string  `json:"expiresAt"`
	DaysLeft     int     `json:"daysLeft"`
	Expired      bool    `json:"expired"`
	Plan         string  `json:"plan"`
	DailyUsed    float64 `json:"dailyUsed"`
	DailyLimit   float64 `json:"dailyLimit"`
	DailyResets  string  `json:"dailyResetsAt"`
	PoolUsed     float64 `json:"poolUsed"`
	PoolLimit    float64 `json:"poolLimit"`
	PoolResets   string  `json:"poolResetsAt"`
	Error        string  `json:"error,omitempty"`
}

func usageFor(s *storedAuth) usage {
	u := usage{Email: s.Email, Name: s.Name, ExpiresAt: s.ExpiresAt, Expired: s.expired()}
	if t, ok := s.expiry(); ok {
		u.DaysLeft = int(time.Until(t).Hours() / 24)
	}
	if s.expired() {
		u.Error = "会话已到期"
		return u
	}
	body, status, err := harkGET(s.Token, pathBilling, nil)
	if err != nil || status != http.StatusOK {
		u.Error = fmt.Sprintf("用量查询失败 (HTTP %d)", status)
		return u
	}
	var data struct {
		Plan  struct{ ID, Name string } `json:"plan"`
		Meters struct {
			HarkTokens struct {
				DailyLimit   float64 `json:"dailyLimit"`
				DailyUsed    float64 `json:"dailyUsed"`
				DailyResets  string  `json:"dailyResetsAt"`
				PoolLimit    float64 `json:"poolLimit"`
				PoolUsed     float64 `json:"poolUsed"`
				PoolResets   string  `json:"poolResetsAt"`
			} `json:"harkTokens"`
		} `json:"meters"`
	}
	if json.Unmarshal(body, &data) != nil {
		u.Error = "用量响应解析失败"
		return u
	}
	t := data.Meters.HarkTokens
	u.Plan = data.Plan.Name
	u.DailyUsed, u.DailyLimit, u.DailyResets = t.DailyUsed, t.DailyLimit, t.DailyResets
	u.PoolUsed, u.PoolLimit, u.PoolResets = t.PoolUsed, t.PoolLimit, t.PoolResets
	return u
}

func handleManagementRegister() ([]byte, error) {
	return okEnvelope(map[string]any{
		"resources": []map[string]any{
			{"path": "/quota", "menu": "Hark 用量", "description": "每个账号的到期时间与用量"},
			{"path": "/import", "menu": "Hark 导入", "description": "批量粘贴 session token 导入账号"},
			{"path": "/callback"},
		},
		// Resource routes only answer GET, so the form posts to a management route.
		"routes": []map[string]any{
			{"method": "POST", "path": "/import"},
		},
	})
}

func handleManagement(raw []byte) ([]byte, error) {
	var req struct {
		Path  string     `json:"path"`
		Query url.Values `json:"query"`
	}
	_ = json.Unmarshal(raw, &req)

	// The host hands over the full request path, so match on the tail.
	switch {
	case strings.HasSuffix(req.Path, "/callback"):
		return handleCallback(req.Query)
	case strings.HasSuffix(req.Path, "/import"):
		return handleImport(raw)
	case strings.HasSuffix(req.Path, "/quota"):
		// handled below
	default:
		return errorEnvelope("not_found", "unknown management path: "+req.Path), nil
	}
	list, err := listOwnAccounts()
	if err != nil {
		return nil, err
	}
	var rows []usage
	for _, s := range list {
		rows = append(rows, usageFor(s))
	}
	if wantsJSON(req.Query) {
		payload, _ := json.Marshal(map[string]any{"accounts": rows})
		return managementResponse(200, "application/json; charset=utf-8", payload)
	}
	return managementResponse(200, "text/html; charset=utf-8", quotaPage(rows))
}

// handleImport serves the paste form and, on POST, turns each pasted token
// into an account. Tokens are split on whitespace, commas and semicolons, so a
// whole list can go in at once. Each one is checked against hark before it is
// saved, and an existing account with the same email is replaced.
func handleImport(raw []byte) ([]byte, error) {
	// ManagementRequest carries no json tags, so the host sends the Go field names.
	var req struct {
		Method string `json:"Method"`
		Body   []byte `json:"Body"`
	}
	_ = json.Unmarshal(raw, &req)

	var results []importResult
	if strings.EqualFold(req.Method, http.MethodPost) && len(req.Body) > 0 {
		values, _ := url.ParseQuery(string(req.Body))
		results = importTokens(splitTokens(values.Get("tokens")))
	}
	return managementResponse(200, "text/html; charset=utf-8", importPage(results))
}

// importTokens checks and saves every token at once. hark is the slow part, so
// the work runs with bounded parallelism instead of one request after another.
func importTokens(tokens []string) []importResult {
	results := make([]importResult, len(tokens))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, tok := range tokens {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, tok string) {
			defer wg.Done()
			defer func() { <-sem }()
			s, err := accountFromToken(tok)
			if err != nil {
				results[i] = importResult{Token: maskToken(tok), Error: err.Error()}
				return
			}
			if err := saveAccount(s); err != nil {
				results[i] = importResult{Email: s.Email, Error: err.Error()}
				return
			}
			hostLog("info", "hark: imported "+s.Email)
			results[i] = importResult{Email: s.Email, Name: s.Name, ExpiresAt: s.ExpiresAt}
		}(i, tok)
	}
	wg.Wait()
	return results
}

type importResult struct {
	Token     string
	Email     string
	Name      string
	ExpiresAt string
	Error     string
}

// splitTokens pulls session tokens out of free text. A token is the value of
// the session cookie, which never contains whitespace, so any run of
// separators works as a delimiter.
func splitTokens(text string) []string {
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ',' || r == ';'
	})
	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if i := strings.Index(f, tokenCookie+"="); i >= 0 {
			f = f[i+len(tokenCookie)+1:]
		}
		f = strings.Trim(f, `"'`)
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

func maskToken(tok string) string {
	if len(tok) <= 10 {
		return tok
	}
	return tok[:6] + "…" + tok[len(tok)-4:]
}

// saveAccount writes the credential through the host, which both stores the
// file and loads it into the live auth set, so no restart is needed.
func saveAccount(s *storedAuth) error {
	stored := map[string]any{}
	raw, _ := json.Marshal(s)
	_ = json.Unmarshal(raw, &stored)
	stored["type"] = providerName
	file, _ := json.Marshal(stored)
	payload, err := json.Marshal(map[string]any{
		"name": s.fileName(),
		"json": json.RawMessage(file),
	})
	if err != nil {
		return err
	}
	body, err := hostCall(pluginabi.MethodHostAuthSave, payload)
	if err != nil {
		return err
	}
	var env struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(body, &env) != nil || !env.OK {
		return fmt.Errorf("保存失败: %s", truncate(string(body), 200))
	}
	return nil
}

func importPage(results []importResult) []byte {
	var b strings.Builder
	b.WriteString(`<!doctype html><meta charset=utf-8><title>Hark 导入</title><style>
body{font:13px/1.5 -apple-system,"Segoe UI",sans-serif;background:transparent;color:#1d1d1f;margin:0;padding:16px 12px}
h2{font-size:15px;font-weight:600;margin:0 0 6px}
p{color:#6e6e73;margin:0 0 12px;font-size:12px}
code{background:#f2f2f4;padding:1px 5px;border-radius:4px;color:#1d1d1f}
label{display:block;font-size:12px;color:#6e6e73;margin-bottom:4px}
input{width:280px;background:#fff;color:#1d1d1f;border:1px solid #e2e2e6;border-radius:8px;padding:7px 10px;font-size:13px;margin-bottom:12px}
textarea{width:100%;max-width:760px;height:170px;background:#fff;color:#1d1d1f;border:1px solid #e2e2e6;border-radius:10px;padding:10px 12px;font:12px/1.6 ui-monospace,monospace;box-sizing:border-box;resize:vertical}
textarea:focus{outline:none;border-color:#007aff}
button{margin-top:10px;background:#007aff;color:#fff;border:0;border-radius:8px;padding:8px 18px;cursor:pointer;font-size:13px}
button:hover{background:#0066d6}
table{border-collapse:collapse;margin-top:16px}
td{padding:5px 14px 5px 0;font-size:12px}
.ok{color:#248a3d}.bad{color:#d70015}.dim{color:#8a8a8e}
</style>
<h2>导入 hark 账号</h2>
<p>每行一个 <code>__Secure-hark.session_token</code>，逗号或分号分隔也行，整段 cookie 直接粘也行。重复的邮箱会覆盖旧的。</p>
<label>管理密钥 <span class=dim>就是登录这个面板时用的密钥，填一次会记在浏览器里</span></label><input id=k type=password placeholder="登录面板的管理密钥">
<form id=f><textarea name=tokens placeholder="token1&#10;token2&#10;__Secure-hark.session_token=token3"></textarea><br><button type=submit>导入</button></form>
<p id=m class=bad></p>
<script>
var k = document.getElementById('k');
k.value = localStorage.getItem('hark-mgmt-key') || new URLSearchParams(location.search).get('management_key') || '';
document.getElementById('f').addEventListener('submit', function (e) {
  e.preventDefault();
  var msg = document.getElementById('m');
  msg.textContent = '导入中…';
  localStorage.setItem('hark-mgmt-key', k.value);
  fetch('/v0/management/import', {
    method: 'POST',
    headers: {'X-Management-Key': k.value, 'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams(new FormData(e.target))
  }).then(function (r) {
    if (r.status === 401 || r.status === 403) { msg.textContent = '管理密钥不对'; return ''; }
    return r.text();
  }).then(function (t) {
    if (!t) return;
    document.open(); document.write(t); document.close();
  }).catch(function () { msg.textContent = '请求失败'; });
});
</script>`)
	if len(results) > 0 {
		b.WriteString(`<table>`)
		for _, r := range results {
			if r.Error != "" {
				fmt.Fprintf(&b, `<tr><td class=bad>失败</td><td>%s</td><td class=dim>%s</td></tr>`,
					htmlEscape(firstNonEmpty(r.Email, r.Token)), htmlEscape(r.Error))
				continue
			}
			fmt.Fprintf(&b, `<tr><td class=ok>已导入</td><td>%s</td><td class=dim>%s · 到期 %s</td></tr>`,
				htmlEscape(firstNonEmpty(r.Name, r.Email)), htmlEscape(r.Email), htmlEscape(r.ExpiresAt))
		}
		b.WriteString(`</table>`)
	}
	return []byte(b.String())
}

func wantsJSON(q url.Values) bool {
	v := strings.ToLower(q.Get("format"))
	return v == "json" || q.Get("json") == "1"
}

func quotaPage(rows []usage) []byte {
	var b strings.Builder
	b.WriteString(`<!doctype html><meta charset=utf-8><title>Hark 用量</title><style>
body{font:13px/1.4 -apple-system,"Segoe UI",sans-serif;background:transparent;color:#3a3a3c;margin:0;padding:4px 2px}
table{border-collapse:collapse;width:100%}
th{text-align:left;font-weight:500;color:#8a8a8e;font-size:12px;padding:8px 14px;border-bottom:1px solid #ececee}
td{padding:9px 14px;border-bottom:1px solid #f2f2f4;white-space:nowrap;vertical-align:middle}
tr:hover td{background:#f7f7f8}
.who{font-weight:600;color:#1d1d1f}.mail{color:#8a8a8e;margin-left:8px;font-weight:400}
.plan{color:#6e6e73;font-size:12px}
.meter{display:flex;align-items:center;gap:8px}
.bar{width:64px;height:5px;background:#ececee;border-radius:3px;overflow:hidden;flex:none}
.fill{height:100%;background:#34c759}.warn{background:#ff9f0a}.bad{background:#ff3b30}
.num{color:#6e6e73;font-variant-numeric:tabular-nums;font-size:12px}
.expired{color:#ff3b30}.ok{color:#6e6e73}
.empty{color:#8a8a8e;padding:16px}
</style>`)
	if len(rows) == 0 {
		b.WriteString(`<p class=empty>还没有账号。在面板里添加 hark 凭据后这里会显示。</p>`)
		return []byte(b.String())
	}
	b.WriteString(`<table><tr><th>账号</th><th>套餐</th><th>到期</th><th>今日</th><th>今日重置</th><th>本周期</th><th>周期重置</th></tr>`)
	for _, u := range rows {
		b.WriteString(`<tr><td><span class=who>`)
		b.WriteString(htmlEscape(firstNonEmpty(u.Name, u.Email)))
		b.WriteString(`</span><span class=mail>`)
		b.WriteString(htmlEscape(u.Email))
		b.WriteString(`</span></td><td class=plan>`)
		b.WriteString(htmlEscape(u.Plan))
		b.WriteString(`</td><td>`)
		writeExpiry(&b, u)
		b.WriteString(`</td><td>`)
		writeMeter(&b, u.DailyUsed, u.DailyLimit)
		b.WriteString(`</td><td class=ok>`)
		b.WriteString(resetIn(u.DailyResets))
		b.WriteString(`</td><td>`)
		writeMeter(&b, u.PoolUsed, u.PoolLimit)
		b.WriteString(`</td><td class=ok>`)
		b.WriteString(resetIn(u.PoolResets))
		b.WriteString(`</td></tr>`)
	}
	b.WriteString(`</table>`)
	return []byte(b.String())
}

func writeExpiry(b *strings.Builder, u usage) {
	switch {
	case u.Expired:
		b.WriteString(`<span class=expired>已到期</span>`)
	case u.Error != "":
		b.WriteString(`<span class=expired>` + htmlEscape(u.Error) + `</span>`)
	case u.ExpiresAt != "":
		cls := "ok"
		if u.DaysLeft <= 3 {
			cls = "expired"
		}
		fmt.Fprintf(b, `<span class=%s>%d 天</span>`, cls, u.DaysLeft)
	}
}

// resetIn renders a reset timestamp as how long from now it happens, with the
// absolute time in the tooltip. hark reports these in RFC3339 UTC.
func resetIn(raw string) string {
	if raw == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return htmlEscape(raw)
	}
	local := t.Local().Format("01-02 15:04")
	d := time.Until(t)
	var text string
	switch {
	case d <= 0:
		text = "即将重置"
	case d < time.Hour:
		text = fmt.Sprintf("%d 分钟后", int(d.Minutes()))
	case d < 48*time.Hour:
		text = fmt.Sprintf("%d 小时后", int(d.Hours()))
	default:
		text = fmt.Sprintf("%d 天后", int(d.Hours()/24))
	}
	return fmt.Sprintf(`<span title="%s">%s</span>`, local, text)
}

func writeMeter(b *strings.Builder, used, limit float64) {
	if limit <= 0 {
		return
	}
	pct := used / limit * 100
	if pct > 100 {
		pct = 100
	}
	cls := "fill"
	if pct >= 90 {
		cls = "fill bad"
	} else if pct >= 70 {
		cls = "fill warn"
	}
	fmt.Fprintf(b, `<div class=meter><div class=bar><div class="%s" style="width:%.1f%%"></div></div><span class=num>%s / %s</span></div>`,
		cls, pct, fmtNum(used), fmtNum(limit))
}

func fmtNum(v float64) string {
	switch {
	case v >= 1e6:
		return fmt.Sprintf("%.2fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1fK", v/1e3)
	default:
		return fmt.Sprintf("%.0f", v)
	}
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

// managementResponse builds the body the host decodes into a ManagementResponse.
// That struct carries no json tags, so the keys are the Go field names.
func managementResponse(status int, contentType string, body []byte) ([]byte, error) {
	return okEnvelope(map[string]any{
		"StatusCode": status,
		"Headers":    map[string][]string{"Content-Type": {contentType}},
		"Body":       body,
	})
}

// handleCallback receives the browser once Google has signed in. hark appends
// the session cookie to the callback URL; we stash it against the login state
// so the next poll completes.
func handleCallback(query url.Values) ([]byte, error) {
	state := query.Get("state")
	token := query.Get("token")
	if token == "" {
		token = query.Get("session_token")
	}
	if v, ok := loginFlows.Load(state); ok && token != "" {
		v.(*loginFlow).token = token
	}
	page := []byte("<!doctype html><meta charset=utf-8><title>hark</title>" +
		"<body style=\"font:16px sans-serif;padding:48px;background:#161616;color:#eee\">" +
		"<p>登录完成，回到面板即可。这个标签页可以关掉了。</p></body>")
	return managementResponse(200, "text/html; charset=utf-8", page)
}

func listOwnAccounts() ([]*storedAuth, error) {
	body, err := hostCall(pluginabi.MethodHostAuthList, []byte(`{}`))
	if err != nil {
		return nil, err
	}
	var env struct {
		OK     bool `json:"ok"`
		Result struct {
			Files []struct {
				AuthIndex string `json:"auth_index"`
				Name      string `json:"name"`
			} `json:"files"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &env) != nil {
		return nil, fmt.Errorf("auth list decode failed")
	}
	var out []*storedAuth
	for _, f := range env.Result.Files {
		if !strings.Contains(strings.ToLower(f.Name), "hark") {
			continue
		}
		req, _ := json.Marshal(map[string]string{"auth_index": f.AuthIndex})
		got, err := hostCall(pluginabi.MethodHostAuthGet, req)
		if err != nil {
			continue
		}
		var one struct {
			OK     bool `json:"ok"`
			Result struct {
				JSON json.RawMessage `json:"json"`
			} `json:"result"`
		}
		if json.Unmarshal(got, &one) != nil {
			continue
		}
		if s, err := parseStored(one.Result.JSON); err == nil {
			out = append(out, s)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// hark HTTP
// ---------------------------------------------------------------------------

func browserHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream, */*")
	req.Header.Set("Origin", upstreamHost)
	req.Header.Set("Referer", upstreamHost+"/chat")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-Hark-Locale", "en")
}

func harkDo(token, method, path string, query url.Values, payload []byte) ([]byte, int, error) {
	u, _ := url.Parse(upstreamHost + path)
	if query != nil {
		u.RawQuery = query.Encode()
	}
	var rdr io.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, u.String(), rdr)
	if err != nil {
		return nil, 0, err
	}
	browserHeaders(req)
	req.Header.Set("Cookie", tokenCookie+"="+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return b, resp.StatusCode, nil
}

func harkGET(token, path string, query url.Values) ([]byte, int, error) {
	return harkDo(token, http.MethodGet, path, query, nil)
}

func harkPOST(token, path string, query url.Values, payload []byte) ([]byte, int, error) {
	return harkDo(token, http.MethodPost, path, query, payload)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func okEnvelope(v any) ([]byte, error) {
	result, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(pluginabi.Envelope{OK: true, Result: result})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(pluginabi.Envelope{OK: false, Error: &pluginabi.Error{Code: code, Message: message}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

func randomState() string { return strings.ReplaceAll(newUUID(), "-", "") }

func splitRunes(s string, n int) []string {
	r := []rune(s)
	if len(r) == 0 {
		return nil
	}
	var out []string
	for len(r) > 0 {
		take := n
		if take > len(r) {
			take = len(r)
		}
		out = append(out, string(r[:take]))
		r = r[take:]
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
