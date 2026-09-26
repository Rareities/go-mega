package mega

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// Default settings
const (
	API_URL                    = "https://g.api.mega.co.nz"
	BASE_DOWNLOAD_URL          = "https://mega.co.nz"
	RETRIES                    = 10
	DOWNLOAD_WORKERS           = 3
	MAX_DOWNLOAD_WORKERS       = 30
	UPLOAD_WORKERS             = 1
	MAX_UPLOAD_WORKERS         = 30
	TIMEOUT                    = time.Second * 10
	HTTPSONLY                  = false
	minSleepTime               = 10 * time.Millisecond // for retries
	maxSleepTime               = 5 * time.Second       // for retries
	X_MEGA_USER_AGENT          = ""                    // custom user agent string. Not set if empty
	HASHCASH_CHALLENGE_TIMEOUT = time.Minute * 5       // time limit to solve hashcash challenge
)

type config struct {
	baseurl    string
	retries    int
	dl_workers int
	ul_workers int
	timeout    time.Duration
	https      bool
}

func newConfig() config {
	return config{
		baseurl:    getAPIBaseURL(),
		retries:    RETRIES,
		dl_workers: DOWNLOAD_WORKERS,
		ul_workers: UPLOAD_WORKERS,
		timeout:    TIMEOUT,
		https:      HTTPSONLY,
	}
}

// Set mega service base url
func (c *config) SetAPIUrl(u string) {
	if strings.HasSuffix(u, "/") {
		u = strings.TrimRight(u, "/")
	}
	c.baseurl = u
}

// Set number of retries for api calls
func (c *config) SetRetries(r int) {
	c.retries = r
}

// Set concurrent download workers
func (c *config) SetDownloadWorkers(w int) error {
	if w <= 0 {
		return EWORKER_COUNT_INVALID
	}
	if w <= MAX_DOWNLOAD_WORKERS {
		c.dl_workers = w
		return nil
	}

	return EWORKER_LIMIT_EXCEEDED
}

// Set connection timeout
func (c *config) SetTimeOut(t time.Duration) {
	c.timeout = t
}

// Set concurrent upload workers
func (c *config) SetUploadWorkers(w int) error {
	if w <= 0 {
		return EWORKER_COUNT_INVALID
	}
	if w <= MAX_UPLOAD_WORKERS {
		c.ul_workers = w
		return nil
	}

	return EWORKER_LIMIT_EXCEEDED
}

// Set use https for transfers
func (c *config) SetHTTPS(e bool) {
	c.https = e
}

type Mega struct {
	config
	// Version of the account
	accountVersion int
	// Salt for the account if accountVersion > 1
	accountSalt []byte
	// Sequence number
	sn int64
	// Server state sn
	ssn string
	// Session ID
	sid string
	// Master key
	k []byte
	// User handle
	uh []byte
	// Filesystem object
	FS *MegaFS
	// HTTP Client
	client *http.Client
	// Loggers
	logf   func(format string, v ...any)
	debugf func(format string, v ...any)
	// apiMu protects lazy initialization of apiGate. The gate itself is
	// context-aware so callers waiting behind another API request can cancel.
	apiMu   sync.Mutex
	apiGate chan struct{}
	// pollEvents has a session lifetime independent from individual operations.
	eventMu     sync.Mutex
	eventCancel context.CancelFunc
	eventDone   chan struct{}
	// mutex to protext waitEvents
	waitEventsMu sync.Mutex
	// Outstanding channels to close to indicate events all received
	waitEvents []chan struct{}
}

func contextOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (m *Mega) acquireAPIGate(ctx context.Context) (func(), error) {
	m.apiMu.Lock()
	if m.apiGate == nil {
		m.apiGate = make(chan struct{}, 1)
	}
	gate := m.apiGate
	m.apiMu.Unlock()

	select {
	case gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-gate
			return nil, err
		}
		return func() { <-gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close stops this client's session-scoped event poller. It does not close
// the caller-owned HTTP client and is safe to call more than once.
func (m *Mega) Close() error {
	m.eventMu.Lock()
	defer m.eventMu.Unlock()
	m.stopEventPollerLocked()
	return nil
}

// stopEventPollerLocked cancels and joins the session poller. eventMu must be
// held by the caller; pollEvents never acquires it.
func (m *Mega) stopEventPollerLocked() {
	if m.eventCancel != nil {
		m.eventCancel()
	}
	if m.eventDone != nil {
		<-m.eventDone
	}
	m.eventCancel = nil
	m.eventDone = nil
}

func (m *Mega) startEventPoller() {
	m.eventMu.Lock()
	defer m.eventMu.Unlock()
	m.stopEventPollerLocked()
	ctx, cancel := context.WithCancel(context.Background())
	m.eventCancel = cancel
	done := make(chan struct{})
	m.eventDone = done
	go func() {
		defer close(done)
		m.pollEvents(ctx)
	}()
}

// Filesystem node types
const (
	FILE   = 0
	FOLDER = 1
	ROOT   = 2
	INBOX  = 3
	TRASH  = 4
)

// Filesystem node
type Node struct {
	fs       *MegaFS
	name     string
	hash     string
	parent   *Node
	children []*Node
	ntype    int
	size     int64
	ts       time.Time
	meta     NodeMeta
}

func (n *Node) removeChild(c *Node) bool {
	index := -1
	for i, v := range n.children {
		if v.hash == c.hash {
			index = i
			break
		}
	}

	if index >= 0 {
		n.children[index] = n.children[len(n.children)-1]
		n.children = n.children[:len(n.children)-1]
		return true
	}

	return false
}

func (n *Node) addChild(c *Node) {
	if n != nil {
		n.children = append(n.children, c)
	}
}

func (n *Node) getChildren() []*Node {
	return n.children
}

func (n *Node) GetType() int {
	n.fs.mutex.Lock()
	defer n.fs.mutex.Unlock()
	return n.ntype
}

func (n *Node) GetSize() int64 {
	n.fs.mutex.Lock()
	defer n.fs.mutex.Unlock()
	return n.size
}

func (n *Node) GetTimeStamp() time.Time {
	n.fs.mutex.Lock()
	defer n.fs.mutex.Unlock()
	return n.ts
}

func (n *Node) GetName() string {
	n.fs.mutex.Lock()
	defer n.fs.mutex.Unlock()
	return n.name
}

func (n *Node) GetHash() string {
	n.fs.mutex.Lock()
	defer n.fs.mutex.Unlock()
	return n.hash
}

type NodeMeta struct {
	key     []byte
	compkey []byte
	iv      []byte
	mac     []byte
}

// Mega filesystem object
type MegaFS struct {
	root   *Node
	trash  *Node
	inbox  *Node
	sroots []*Node
	lookup map[string]*Node
	skmap  map[string]string
	mutex  sync.Mutex
}

// Get filesystem root node
func (fs *MegaFS) GetRoot() *Node {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	return fs.root
}

// Get filesystem trash node
func (fs *MegaFS) GetTrash() *Node {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	return fs.trash
}

// Get inbox node
func (fs *MegaFS) GetInbox() *Node {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	return fs.inbox
}

// Get a node pointer from its hash
func (fs *MegaFS) HashLookup(h string) *Node {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	return fs.hashLookup(h)
}

func (fs *MegaFS) hashLookup(h string) *Node {
	if node, ok := fs.lookup[h]; ok {
		return node
	}

	return nil
}

// Get the list of child nodes for a given node
func (fs *MegaFS) GetChildren(n *Node) ([]*Node, error) {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	var empty []*Node

	if n == nil {
		return empty, EARGS
	}

	node := fs.hashLookup(n.hash)
	if node == nil {
		return empty, ENOENT
	}

	return node.getChildren(), nil
}

// Retrieve all the nodes in the given node tree path by name
// This method returns array of nodes upto the matched subpath
// (in same order as input names array) even if the target node is not located.
func (fs *MegaFS) PathLookup(root *Node, ns []string) ([]*Node, error) {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	if root == nil {
		return nil, EARGS
	}

	var err error
	var found = true

	nodepath := []*Node{}

	children := root.children
	for _, name := range ns {
		found = false
		for _, n := range children {
			if n.name == name {
				nodepath = append(nodepath, n)
				children = n.children
				found = true
				break
			}
		}

		if !found {
			break
		}
	}

	if !found {
		err = ENOENT
	}

	return nodepath, err
}

// Get top level directory nodes shared by other users
func (fs *MegaFS) GetSharedRoots() []*Node {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	return fs.sroots
}

func newMegaFS() *MegaFS {
	fs := &MegaFS{
		lookup: make(map[string]*Node),
		skmap:  make(map[string]string),
	}
	return fs
}

func New() *Mega {
	max := big.NewInt(0x100000000)
	bigx, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err) // this should be returned, but this is a public interface
	}
	cfg := newConfig()
	mgfs := newMegaFS()
	m := &Mega{
		config: cfg,
		sn:     bigx.Int64(),
		FS:     mgfs,
		client: newHttpClient(cfg.timeout),
	}
	m.SetLogger(log.Printf)
	m.SetDebugger(nil)
	return m
}

// SetClient sets the HTTP client in use
func (m *Mega) SetClient(client *http.Client) *Mega {
	m.client = client
	return m
}

// discardLogf discards the log messages
func discardLogf(format string, v ...any) {
}

// Returns an opaque string representing the session
func (m *Mega) GetSessionID() string {
	return m.sid
}

func (m *Mega) GetMasterKey() []byte {
	return m.k
}

// "Login" using the session ID (for API auth) and master key (for decryption). Alternative to logging in with username/password
// This can be used to import back a session exported with GetSessionID and GetMasterKey without requiring the password again
func (m *Mega) LoginWithKeys(sessionId string, masterKey []byte) error {
	return m.LoginWithKeysContext(context.Background(), sessionId, masterKey)
}

// LoginWithKeysContext restores a saved session using the supplied context.
func (m *Mega) LoginWithKeysContext(ctx context.Context, sessionId string, masterKey []byte) error {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	_ = m.Close()
	m.sid = sessionId
	m.k = masterKey
	return m.postAuthInitContext(ctx)
}

// SetLogger sets the logger for important messages.  By default this
// is log.Printf.  Use nil to discard the messages.
func (m *Mega) SetLogger(logf func(format string, v ...any)) *Mega {
	if logf == nil {
		logf = discardLogf
	}
	m.logf = logf
	return m
}

// SetDebugger sets the logger for debug messages.  By default these
// messages are not output.
func (m *Mega) SetDebugger(debugf func(format string, v ...any)) *Mega {
	if debugf == nil {
		debugf = discardLogf
	}
	m.debugf = debugf
	return m
}

// backOffSleep sleeps for the time pointed to then adjusts it by
// doubling it up to a maximum of maxSleepTime.
//
// This produces a truncated exponential backoff sleep
func backOffSleep(pt *time.Duration) {
	time.Sleep(*pt)
	*pt *= 2
	if *pt > maxSleepTime {
		*pt = maxSleepTime
	}
}

func advanceBackoff(pt *time.Duration) {
	*pt *= 2
	if *pt > maxSleepTime {
		*pt = maxSleepTime
	}
}

// apiAction returns the action code only for a single-command API request.
func apiAction(request []byte) string {
	var commands []struct {
		Action string `json:"a"`
	}
	if err := json.Unmarshal(request, &commands); err != nil || len(commands) != 1 {
		return ""
	}
	return commands[0].Action
}

// apiRequestedPutNodeType extracts the type requested by the pinned p callers.
// Upload.Finish and CreateDir each submit one node with its requested type in n[0].t.
func apiRequestedPutNodeType(request []byte) (int, bool) {
	var commands []struct {
		Action string `json:"a"`
		Nodes  []struct {
			Type json.RawMessage `json:"t"`
		} `json:"n"`
	}
	if err := json.Unmarshal(request, &commands); err != nil || len(commands) != 1 || commands[0].Action != "p" || len(commands[0].Nodes) != 1 {
		return 0, false
	}
	typeCode, valid := decodeAPIErrorCode(commands[0].Nodes[0].Type)
	if !valid || (typeCode != FILE && typeCode != FOLDER) {
		return 0, false
	}
	return int(typeCode), true
}

// isRetryableAPIAction is an explicit allowlist of read-only API actions.
func isRetryableAPIAction(action string) bool {
	switch action {
	case "us0", "ug", "uq", "f", "g":
		return true
	default:
		return false
	}
}

func isRetryableAPIStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func isTLSAPIError(err error) bool {
	var verificationErr *tls.CertificateVerificationError
	var recordHeaderErr tls.RecordHeaderError
	var alertErr tls.AlertError
	var unknownAuthorityErr x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidCertErr x509.CertificateInvalidError
	if errors.As(err, &verificationErr) || errors.As(err, &recordHeaderErr) ||
		errors.As(err, &alertErr) || errors.As(err, &unknownAuthorityErr) ||
		errors.As(err, &hostnameErr) || errors.As(err, &invalidCertErr) {
		return true
	}
	// Some TLS alerts are surfaced by net/http as plain errors rather than
	// exported TLS error types. Fail closed for those diagnostics as well.
	return strings.Contains(strings.ToLower(err.Error()), "tls:")
}

func isRetryableAPITransportError(err error) bool {
	// The public request API has no caller context. If the HTTP stack reports
	// cancellation/deadline anyway, fail immediately; otherwise retry only
	// errors with an explicit transient network classification (or truncation).
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || isTLSAPIError(err) {
		return false
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && (networkErr.Timeout() || networkErr.Temporary())
}

// parseBoundedRetryAfter distinguishes an absent/invalid header (use normal
// backoff) from a valid server delay that exceeds this client's sleep bound
// (do not retry early against the server's instruction).
func parseBoundedRetryAfter(value string, now time.Time) (delay time.Duration, present, withinBound bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false, true
	}
	// RFC delta-seconds is a non-negative decimal integer. Treat an integer
	// overflow as an over-bound server delay, not as a malformed/absent header
	// that would permit an earlier retry.
	deltaSeconds := true
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			deltaSeconds = false
			break
		}
	}
	if deltaSeconds {
		seconds, err := strconv.ParseInt(value, 10, 64)
		if err != nil || seconds > int64(maxSleepTime/time.Second) {
			return 0, true, false
		}
		delay = time.Duration(seconds) * time.Second
		return delay, true, true
	}
	date, err := http.ParseTime(value)
	if err != nil {
		return 0, false, true
	}
	delay = date.Sub(now)
	if delay < 0 {
		delay = 0
	}
	return delay, true, delay <= maxSleepTime
}

func closeAPIResponse(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}

func decodeAPIErrorCode(raw json.RawMessage) (ErrorMsg, bool) {
	data := bytes.TrimSpace(raw)
	if len(data) == 0 || bytes.Equal(data, []byte("-0")) || (data[0] != '-' && (data[0] < '0' || data[0] > '9')) {
		return 0, false
	}

	var value int64
	if err := json.Unmarshal(data, &value); err != nil {
		return 0, false
	}
	code := int(value)
	if int64(code) != value {
		return 0, false
	}
	return ErrorMsg(code), true
}

func apiObjectErrorCode(raw json.RawMessage) (ErrorMsg, bool, error) {
	data := bytes.TrimSpace(raw)
	if len(data) == 0 || data[0] != '{' {
		return 0, false, nil
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return 0, false, EBADRESP
	}
	rawCode, found := fields["err"]
	if !found {
		return 0, false, nil
	}
	code, valid := decodeAPIErrorCode(rawCode)
	if !valid {
		return 0, true, EBADRESP
	}
	return code, true, nil
}

func apiDeleteResponseError(response []json.RawMessage) error {
	if len(response) != 1 {
		return EBADRESP
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response[0], &fields); err != nil || fields == nil {
		return EBADRESP
	}
	rawResults, found := fields["r"]
	if !found {
		return EBADRESP
	}
	rawResults = bytes.TrimSpace(rawResults)
	if len(rawResults) == 0 || rawResults[0] != '[' {
		return EBADRESP
	}
	var results []json.RawMessage
	if err := json.Unmarshal(rawResults, &results); err != nil {
		return EBADRESP
	}
	if len(results) == 0 {
		// Evidence: https://github.com/meganz/sdk/blob/master/src/commands.cpp#L1594-L1631
		// CommandDelNode::procresult starts e as API_OK and only overwrites it
		// when a numeric r entry exists. This is current SDK evidence, not a
		// contract established by the pinned Go source.
		return nil
	}
	if len(results) != 1 {
		return EBADRESP
	}
	code, valid := decodeAPIErrorCode(results[0])
	if !valid {
		return EBADRESP
	}
	return parseError(code)
}

func apiUploadURLResponseError(response []json.RawMessage) error {
	if len(response) != 1 {
		return EBADRESP
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response[0], &fields); err != nil || fields == nil {
		return EBADRESP
	}
	rawURL, found := fields["p"]
	if !found {
		return EBADRESP
	}
	var target string
	if err := json.Unmarshal(rawURL, &target); err != nil || target == "" {
		return EBADRESP
	}
	parsedURL, err := url.Parse(target)
	if err != nil || !parsedURL.IsAbs() || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return EBADRESP
	}
	return nil
}

func apiLoginResponseError(response []json.RawMessage) error {
	if len(response) != 1 {
		return EBADRESP
	}

	var result LoginResp
	if err := json.Unmarshal(response[0], &result); err != nil {
		return EBADRESP
	}
	if result.Csid == "" || result.Privk == "" || result.Key == "" {
		return EBADRESP
	}
	return nil
}

func apiLinkResponseError(response []json.RawMessage) error {
	if len(response) != 1 {
		return EBADRESP
	}
	var link string
	if err := json.Unmarshal(response[0], &link); err != nil || link == "" {
		return EBADRESP
	}
	return nil
}

// apiPutNodesResponseError validates the first node consumed by Upload.Finish
// and CreateDir. Their addFSNode path needs h, p, u, t, a, and k. Additional
// returned nodes are accepted, and the first node's t must match the request's
// n[0].t. No broader server-side node schema is asserted here.
func apiPutNodesResponseError(response []json.RawMessage, requestedType int) error {
	if len(response) != 1 {
		return EBADRESP
	}
	if requestedType != FILE && requestedType != FOLDER {
		return EBADRESP
	}
	var result UploadCompleteResp
	if err := json.Unmarshal(response[0], &result); err != nil || len(result.F) == 0 {
		return EBADRESP
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response[0], &fields); err != nil || fields == nil {
		return EBADRESP
	}
	rawNodes, found := fields["f"]
	if !found {
		return EBADRESP
	}
	rawNodes = bytes.TrimSpace(rawNodes)
	if len(rawNodes) == 0 || rawNodes[0] != '[' {
		return EBADRESP
	}
	var nodes []json.RawMessage
	if err := json.Unmarshal(rawNodes, &nodes); err != nil || len(nodes) == 0 {
		return EBADRESP
	}
	firstNode := bytes.TrimSpace(nodes[0])
	if len(firstNode) == 0 || firstNode[0] != '{' {
		return EBADRESP
	}
	var nodeFields map[string]json.RawMessage
	if err := json.Unmarshal(firstNode, &nodeFields); err != nil {
		return EBADRESP
	}
	node := result.F[0]
	if node.Hash == "" || node.Parent == "" || node.User == "" || node.Attr == "" || node.Key == "" || !strings.Contains(node.Key, ":") {
		return EBADRESP
	}
	typeCode, valid := decodeAPIErrorCode(nodeFields["t"])
	if !valid || int(typeCode) != requestedType {
		return EBADRESP
	}
	return nil
}

func apiResponseError(action string, request, buf []byte) error {
	data := bytes.TrimSpace(buf)
	if len(data) == 0 || !json.Valid(data) {
		return EBADRESP
	}

	if data[0] == '-' {
		code, valid := decodeAPIErrorCode(data)
		if !valid {
			return EBADRESP
		}
		return parseError(code)
	}
	if data[0] != '[' {
		return EBADRESP
	}

	var response []json.RawMessage
	if err := json.Unmarshal(data, &response); err != nil || len(response) == 0 {
		return EBADRESP
	}
	if len(response) == 1 {
		if code, valid := decodeAPIErrorCode(response[0]); valid {
			if code == 0 && action != "m" && action != "a" && action != "d" {
				return EBADRESP
			}
			return parseError(code)
		}
		if code, found, err := apiObjectErrorCode(response[0]); err != nil {
			return err
		} else if found {
			if code == 0 {
				switch action {
				case "d":
					return apiDeleteResponseError(response)
				case "p":
					requestedType, valid := apiRequestedPutNodeType(request)
					if !valid {
						return EBADRESP
					}
					return apiPutNodesResponseError(response, requestedType)
				case "u":
					return apiUploadURLResponseError(response)
				case "us":
					return apiLoginResponseError(response)
				case "l":
					return EBADRESP
				default:
					return EBADRESP
				}
			}
			return parseError(code)
		}
		if bytes.Equal(bytes.TrimSpace(response[0]), []byte("null")) {
			return EBADRESP
		}
	}

	switch action {
	case "m", "a":
		// The pinned source's known numeric API_OK response is exactly [0].
		// No other success shape is assumed for these response-ignoring actions.
		return EBADRESP
	case "d":
		return apiDeleteResponseError(response)
	case "p":
		requestedType, valid := apiRequestedPutNodeType(request)
		if !valid {
			return EBADRESP
		}
		return apiPutNodesResponseError(response, requestedType)
	case "u":
		return apiUploadURLResponseError(response)
	case "us":
		return apiLoginResponseError(response)
	case "l":
		return apiLinkResponseError(response)
	case "us0", "ug", "uq", "f", "g":
		return apiReadResponseError(action, response)
	default:
		return EBADRESP
	}
}

func apiRequiredString(fields map[string]json.RawMessage, name string) (string, bool) {
	raw, ok := fields[name]
	if !ok {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		return "", false
	}
	return value, true
}

func apiRequiredInt64(fields map[string]json.RawMessage, name string) (int64, bool) {
	raw, ok := fields[name]
	if !ok {
		return 0, false
	}
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, false
	}
	return value, true
}

func apiRequiredUint64(fields map[string]json.RawMessage, name string) (uint64, bool) {
	raw, ok := fields[name]
	if !ok {
		return 0, false
	}
	var value uint64
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, false
	}
	return value, true
}

func apiFilesystemNodeError(raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return EBADRESP
	}
	var node FSNode
	if err := json.Unmarshal(raw, &node); err != nil {
		return EBADRESP
	}
	if _, ok := apiRequiredString(fields, "h"); !ok {
		return EBADRESP
	}
	typeCode, valid := decodeAPIErrorCode(fields["t"])
	if !valid {
		return EBADRESP
	}
	node.T = int(typeCode)
	switch node.T {
	case ROOT, INBOX, TRASH:
		return nil
	case FILE, FOLDER:
	default:
		return EBADRESP
	}
	if _, ok := apiRequiredString(fields, "u"); !ok {
		return EBADRESP
	}
	if _, ok := apiRequiredString(fields, "a"); !ok {
		return EBADRESP
	}
	key, ok := apiRequiredString(fields, "k")
	if !ok {
		return EBADRESP
	}
	keyUser, itemKey, found := strings.Cut(key, ":")
	if !found || keyUser == "" || itemKey == "" {
		return EBADRESP
	}
	if _, ok := apiRequiredInt64(fields, "ts"); !ok {
		return EBADRESP
	}
	if node.T == FILE {
		size, ok := apiRequiredInt64(fields, "s")
		if !ok || size < 0 {
			return EBADRESP
		}
	}
	sharedUser, userPresent := fields["su"]
	sharedKey, keyPresent := fields["sk"]
	if userPresent != keyPresent {
		return EBADRESP
	}
	sharedRoot := false
	if userPresent {
		var user, shareKey string
		if json.Unmarshal(sharedUser, &user) != nil || json.Unmarshal(sharedKey, &shareKey) != nil || user == "" || shareKey == "" {
			return EBADRESP
		}
		sharedRoot = node.T == FOLDER
	}
	// Shared roots can be top-level and therefore have no parent handle. Keep
	// accepting that shape, which addFSNode represents as a separate shared
	// root, while rejecting an absent/empty parent on ordinary files/folders.
	if rawParent, present := fields["p"]; present {
		var parent string
		if json.Unmarshal(rawParent, &parent) != nil || (parent == "" && !sharedRoot) {
			return EBADRESP
		}
	} else if !sharedRoot {
		return EBADRESP
	}
	return nil
}

func apiFilesResponseError(raw json.RawMessage, fields map[string]json.RawMessage) error {
	rawNodes, found := fields["f"]
	if !found {
		return EBADRESP
	}
	rawNodes = bytes.TrimSpace(rawNodes)
	if len(rawNodes) == 0 || rawNodes[0] != '[' {
		return EBADRESP
	}
	var nodes []json.RawMessage
	if err := json.Unmarshal(rawNodes, &nodes); err != nil {
		return EBADRESP
	}
	for _, node := range nodes {
		if err := apiFilesystemNodeError(node); err != nil {
			return err
		}
	}
	if _, ok := apiRequiredString(fields, "sn"); !ok {
		return EBADRESP
	}
	// "ok" contains optional shared-folder keys; if present, each entry must
	// be complete because getFileSystem installs these keys before its nodes.
	if rawKeys, present := fields["ok"]; present {
		rawKeys = bytes.TrimSpace(rawKeys)
		if len(rawKeys) == 0 || rawKeys[0] != '[' {
			return EBADRESP
		}
		var keys []json.RawMessage
		if err := json.Unmarshal(rawKeys, &keys); err != nil {
			return EBADRESP
		}
		for _, rawKey := range keys {
			var keyFields map[string]json.RawMessage
			if err := json.Unmarshal(rawKey, &keyFields); err != nil || keyFields == nil {
				return EBADRESP
			}
			if _, ok := apiRequiredString(keyFields, "h"); !ok {
				return EBADRESP
			}
			if _, ok := apiRequiredString(keyFields, "k"); !ok {
				return EBADRESP
			}
		}
	}
	var result FilesResp
	if err := json.Unmarshal(raw, &result); err != nil {
		return EBADRESP
	}
	return nil
}

// apiReadResponseError validates the fields consumed by each pinned read
// callsite, without asserting unrelated or evolving response fields.
func apiReadResponseError(action string, response []json.RawMessage) error {
	if len(response) != 1 {
		return EBADRESP
	}
	object := bytes.TrimSpace(response[0])
	if len(object) == 0 || object[0] != '{' {
		return EBADRESP
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(object, &fields); err != nil || fields == nil {
		return EBADRESP
	}
	switch action {
	case "us0":
		version, valid := decodeAPIErrorCode(fields["v"])
		if !valid || version <= 0 {
			return EBADRESP
		}
		if version == 2 {
			if _, ok := apiRequiredString(fields, "s"); !ok {
				return EBADRESP
			}
		}
		return nil
	case "ug":
		var result UserResp
		if err := json.Unmarshal(object, &result); err != nil {
			return EBADRESP
		}
		if _, ok := apiRequiredString(fields, "u"); !ok {
			return EBADRESP
		}
		return nil
	case "uq":
		var result QuotaResp
		if err := json.Unmarshal(object, &result); err != nil {
			return EBADRESP
		}
		if _, ok := apiRequiredUint64(fields, "mstrg"); !ok {
			return EBADRESP
		}
		if _, ok := apiRequiredUint64(fields, "cstrg"); !ok {
			return EBADRESP
		}
		return nil
	case "f":
		return apiFilesResponseError(response[0], fields)
	case "g":
		var result DownloadResp
		if err := json.Unmarshal(object, &result); err != nil {
			return EBADRESP
		}
		if rawErr, present := fields["e"]; present {
			code, valid := decodeAPIErrorCode(rawErr)
			if !valid {
				return EBADRESP
			}
			if code != 0 {
				return parseError(code)
			}
		}
		target, ok := apiRequiredString(fields, "g")
		if !ok {
			return EBADRESP
		}
		if _, ok := apiRequiredString(fields, "at"); !ok {
			return EBADRESP
		}
		if _, ok := apiRequiredUint64(fields, "s"); !ok {
			return EBADRESP
		}
		parsedURL, err := url.Parse(target)
		if err != nil || !parsedURL.IsAbs() || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
			return EBADRESP
		}
		return nil
	default:
		return EBADRESP
	}
}

func uncertainOutcomeError(action string, err error) error {
	return &UncertainOutcomeError{Action: action, Err: err}
}

func apiStatusError(resp *http.Response, sid string) error {
	return &HTTPStatusError{StatusCode: resp.StatusCode, Status: redactSessionID(resp.Status, sid)}
}

func (m *Mega) doAPIRequest(req *http.Request, retryable bool) (*http.Response, error) {
	if retryable {
		return m.client.Do(req)
	}

	// Prevent net/http from replaying a POST while following a redirect.
	client := *m.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client.Do(req)
}

// API request method
func (m *Mega) api_request(r []byte) ([]byte, error) {
	return m.api_request_context(context.Background(), r)
}

// api_request_context is the context-aware form of api_request.
func (m *Mega) api_request_context(ctx context.Context, r []byte) ([]byte, error) {
	return m.apiRequestWithHashCashContext(ctx, r, solveHashCashChallengeContext)
}

// apiRequestWithHashCash keeps the request path testable with a deterministic
// solver while production uses solveHashCashChallenge through api_request.
func (m *Mega) apiRequestWithHashCash(r []byte, solveHashCash func(string, int, time.Duration, int) (string, error)) (body []byte, retErr error) {
	return m.apiRequestWithHashCashContext(context.Background(), r, func(_ context.Context, token string, easiness int, timeout time.Duration, workers int) (string, error) {
		return solveHashCash(token, easiness, timeout, workers)
	})
}

func (m *Mega) apiRequestWithHashCashContext(ctx context.Context, r []byte, solveHashCash func(context.Context, string, int, time.Duration, int) (string, error)) (body []byte, retErr error) {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	action := apiAction(r)
	retryable := isRetryableAPIAction(action)
	attempts := 1
	if retryable && m.retries > 0 {
		attempts += m.retries
	}

	// Serialize API requests without making queued callers wait unconditionally.
	release, err := m.acquireAPIGate(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		m.sn++
		release()
	}()

	url := fmt.Sprintf("%s/cs?id=%d", m.baseurl, m.sn)
	if m.sid != "" {
		url = fmt.Sprintf("%s&sid=%s", url, m.sid)
	}
	defer func() {
		retErr = sanitizeAPIError(retErr, m.sid)
	}()
	uncertain := func(err error) error {
		return uncertainOutcomeError(action, sanitizeAPIError(err, m.sid))
	}

	sleepTime := minSleepTime // initial backoff time
	var lastErr error
	var retryDelay time.Duration
	var retryDelaySet bool
	for i := 0; i < attempts; i++ {
		if err := ctx.Err(); err != nil {
			if !retryable && lastErr != nil {
				return nil, uncertain(err)
			}
			return nil, err
		}
		if i != 0 {
			m.debugf("Retry API request %d/%d: %v", i, attempts-1, sanitizeAPIError(lastErr, m.sid))
			if retryDelaySet {
				if err := sleepContext(ctx, retryDelay); err != nil {
					return nil, err
				}
				retryDelaySet = false
				sleepTime *= 2
				if sleepTime > maxSleepTime {
					sleepTime = maxSleepTime
				}
			} else {
				if err := sleepContext(ctx, sleepTime); err != nil {
					return nil, err
				}
				sleepTime *= 2
				if sleepTime > maxSleepTime {
					sleepTime = maxSleepTime
				}
			}
		}

		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(r))
		if err != nil {
			return nil, err
		}
		addRequestHeaders(req)
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		resp, err := m.doAPIRequest(req, retryable)
		if err != nil {
			closeAPIResponse(resp)
			lastErr = err
			if !retryable {
				return nil, uncertain(err)
			}
			if !isRetryableAPITransportError(err) {
				return nil, err
			}
			continue
		}
		if resp == nil {
			lastErr = errors.New("HTTP client returned a nil response")
			if !retryable {
				return nil, uncertain(lastErr)
			}
			return nil, lastErr
		}

		// A valid challenge is an explicit protocol continuation, including for
		// non-read actions. Without established rejection semantics, an unusable
		// challenge leaves a non-read request's outcome uncertain.
		if resp.StatusCode == http.StatusPaymentRequired {
			challengeErr := apiStatusError(resp, m.sid)
			sleepTime = minSleepTime
			easiness, token, valid := parseHashcash(resp.Header.Get("X-Hashcash"))
			closeAPIResponse(resp)
			if !valid {
				lastErr = challengeErr
				if !retryable {
					return nil, uncertain(challengeErr)
				}
				return nil, challengeErr
			}

			cashValue, solveErr := solveHashCash(ctx, token, easiness, HASHCASH_CHALLENGE_TIMEOUT, halfCPUCores())
			if ctxErr := ctx.Err(); ctxErr != nil {
				if !retryable {
					return nil, uncertain(ctxErr)
				}
				return nil, ctxErr
			}
			if solveErr != nil || cashValue == "" {
				if solveErr != nil {
					m.debugf("Failed to solve hashcash challenge: %v", sanitizeAPIError(solveErr, m.sid))
				} else {
					m.debugf("Failed to solve hashcash challenge: empty cash value")
				}
				failureErr := challengeErr
				if solveErr != nil {
					failureErr = errors.Join(challengeErr, solveErr)
				} else if cashValue == "" {
					failureErr = errors.Join(challengeErr, errors.New("hashcash solver returned an empty solution"))
				}
				lastErr = failureErr
				failureErr = sanitizeAPIError(failureErr, m.sid)
				if !retryable {
					return nil, uncertain(failureErr)
				}
				return nil, failureErr
			}

			req, err = http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(r))
			if err != nil {
				return nil, err
			}
			addHashCashRequestHeaders(req, token, cashValue)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			resp, err = m.doAPIRequest(req, retryable)
			if err != nil {
				closeAPIResponse(resp)
				lastErr = err
				if !retryable {
					return nil, uncertain(err)
				}
				if !isRetryableAPITransportError(err) {
					return nil, err
				}
				continue
			}
			if resp == nil {
				lastErr = errors.New("HTTP client returned a nil response")
				if !retryable {
					return nil, uncertain(lastErr)
				}
				return nil, lastErr
			}
			if resp.StatusCode == http.StatusPaymentRequired {
				statusErr := apiStatusError(resp, m.sid)
				closeAPIResponse(resp)
				if !retryable {
					return nil, uncertain(statusErr)
				}
				return nil, statusErr
			}
		}

		if resp.StatusCode != http.StatusOK {
			statusErr := apiStatusError(resp, m.sid)
			closeAPIResponse(resp)
			if !retryable {
				return nil, uncertain(statusErr)
			}
			lastErr = statusErr
			if !isRetryableAPIStatus(resp.StatusCode) {
				return nil, statusErr
			}
			delay, present, withinBound := parseBoundedRetryAfter(resp.Header.Get("Retry-After"), time.Now())
			if present && !withinBound {
				return nil, statusErr
			}
			if present && delay > 0 {
				retryDelay = delay
				retryDelaySet = true
			}
			continue
		}
		if resp.Body == nil {
			lastErr = fmt.Errorf("%w: response body is nil", EBADRESP)
			if !retryable {
				return nil, uncertain(lastErr)
			}
			return nil, lastErr
		}

		buf, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			if !retryable {
				return nil, uncertain(readErr)
			}
			if isRetryableAPITransportError(readErr) {
				continue
			}
			return nil, readErr
		}
		if closeErr != nil {
			lastErr = closeErr
			if !retryable {
				return nil, uncertain(closeErr)
			}
			if isRetryableAPITransportError(closeErr) {
				continue
			}
			return nil, closeErr
		}

		if responseErr := apiResponseError(action, r, buf); responseErr != nil {
			if errors.Is(responseErr, EBADRESP) {
				if !retryable {
					return buf, uncertain(responseErr)
				}
				return buf, responseErr
			}
			if errors.Is(responseErr, EAGAIN) && retryable {
				lastErr = responseErr
				continue
			}
			return buf, responseErr
		}
		return buf, nil
	}

	if lastErr == nil {
		lastErr = errors.New("API request exhausted without a response")
	}
	return nil, lastErr
}

// prelogin call
func (m *Mega) prelogin(email string) error {
	return m.preloginContext(context.Background(), email)
}

func (m *Mega) preloginContext(ctx context.Context, email string) error {
	var msg [1]PreloginMsg
	var res [1]PreloginResp

	email = strings.ToLower(email) // mega uses lowercased emails for login purposes - FIXME is this true for prelogin?

	msg[0].Cmd = "us0"
	msg[0].User = email

	req, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	result, err := m.api_request_context(ctx, req)
	if err != nil {
		return err
	}

	err = json.Unmarshal(result, &res)
	if err != nil {
		return err
	}

	if res[0].Version == 0 {
		return errors.New("prelogin: no version returned")
	} else if res[0].Version > 2 {
		return fmt.Errorf("prelogin: version %d account not supported", res[0].Version)
	} else if res[0].Version == 2 {
		if len(res[0].Salt) == 0 {
			return errors.New("prelogin: no salt returned")
		}
		m.accountSalt, err = base64urldecode(res[0].Salt)
		if err != nil {
			return err
		}
	}
	m.accountVersion = res[0].Version

	return nil
}

// Authenticate and start a session
func (m *Mega) login(email string, passwd string, multiFactor string) error {
	return m.loginContext(context.Background(), email, passwd, multiFactor)
}

func (m *Mega) loginContext(ctx context.Context, email string, passwd string, multiFactor string) error {
	var msg [1]LoginMsg
	var res [1]LoginResp
	var err error
	var result []byte

	email = strings.ToLower(email) // mega uses lowercased emails for login purposes

	passkey, err := password_key(passwd)
	if err != nil {
		return err
	}
	uhandle, err := stringhash(email, passkey)
	if err != nil {
		return err
	}
	m.uh = make([]byte, len(uhandle))
	copy(m.uh, uhandle)

	msg[0].Cmd = "us"
	msg[0].User = email
	msg[0].Mfa = multiFactor

	if m.accountVersion == 1 {
		msg[0].Handle = uhandle
	} else {
		const derivedKeyLength = 2 * aes.BlockSize
		derivedKey := pbkdf2.Key([]byte(passwd), m.accountSalt, 100000, derivedKeyLength, sha512.New)
		authKey := derivedKey[aes.BlockSize:]
		passkey = derivedKey[:aes.BlockSize]

		sessionKey := make([]byte, aes.BlockSize)
		_, err = rand.Read(sessionKey)
		if err != nil {
			return err
		}
		msg[0].Handle = base64urlencode(authKey)
		msg[0].SessionKey = base64urlencode(sessionKey)
	}

	req, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	result, err = m.api_request_context(ctx, req)
	if err != nil {
		return err
	}

	err = json.Unmarshal(result, &res)
	if err != nil {
		return err
	}

	m.k, err = base64urldecode(res[0].Key)
	if err != nil {
		return err
	}
	cipher, err := aes.NewCipher(passkey)
	if err != nil {
		return err
	}
	cipher.Decrypt(m.k, m.k)
	m.sid, err = decryptSessionId(res[0].Privk, res[0].Csid, m.k)
	if err != nil {
		return err
	}
	return nil
}

// Authenticate and start a session
func (m *Mega) Login(email string, passwd string) error {
	return m.MultiFactorLogin(email, passwd, "")
}

// LoginContext authenticates without multi-factor authentication using ctx.
func (m *Mega) LoginContext(ctx context.Context, email string, passwd string) error {
	return m.MultiFactorLoginContext(ctx, email, passwd, "")
}

// MultiFactorLogin - Authenticate and start a session with 2FA
func (m *Mega) MultiFactorLogin(email, passwd, multiFactor string) error {
	return m.MultiFactorLoginContext(context.Background(), email, passwd, multiFactor)
}

// MultiFactorLoginContext authenticates and initializes the session using ctx.
func (m *Mega) MultiFactorLoginContext(ctx context.Context, email, passwd, multiFactor string) error {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	_ = m.Close()
	err := m.preloginContext(ctx, email)
	if err != nil {
		return err
	}

	err = m.loginContext(ctx, email, passwd, multiFactor)
	if err != nil {
		return err
	}

	return m.postAuthInitContext(ctx)
}

// Finish initializing the Mega client after Login*()
func (m *Mega) postAuthInit() error {
	return m.postAuthInitContext(context.Background())
}

func (m *Mega) postAuthInitContext(ctx context.Context) error {

	waitEvent := m.WaitEventsStart()

	err := m.getFileSystemContext(ctx)
	if err != nil {
		m.removeWaitEvent(waitEvent)
		return err
	}

	// Wait until the all the pending events have been received
	if _, err := m.waitEventsContext(ctx, waitEvent, 5*time.Second); err != nil {
		m.removeWaitEvent(waitEvent)
		return err
	}

	return nil
}

// WaitEventsStart - call this before you do the action which might
// generate events then use the returned channel as a parameter to
// WaitEvents to wait for the event(s) to be received.
func (m *Mega) WaitEventsStart() <-chan struct{} {
	ch := make(chan struct{})
	m.waitEventsMu.Lock()
	m.waitEvents = append(m.waitEvents, ch)
	m.waitEventsMu.Unlock()
	return ch
}

// WaitEvents waits for all outstanding events to be received for a
// maximum of duration.  eventChan should be a channel as returned
// from WaitEventStart.
//
// If the timeout elapsed then it returns true otherwise false.
func (m *Mega) WaitEvents(eventChan <-chan struct{}, duration time.Duration) (timedout bool) {
	timedout, _ = m.waitEventsContext(context.Background(), eventChan, duration)
	return timedout
}

func (m *Mega) waitEventsContext(ctx context.Context, eventChan <-chan struct{}, duration time.Duration) (timedout bool, err error) {
	ctx = contextOrBackground(ctx)
	m.debugf("Waiting for events to be finished for %v", duration)
	timer := time.NewTimer(duration)
	select {
	case <-eventChan:
		m.debugf("Events received")
		timedout = false
	case <-timer.C:
		m.debugf("Timeout waiting for events")
		timedout = true
	case <-ctx.Done():
		err = ctx.Err()
	}
	timer.Stop()
	return timedout, err
}

// waitEventsFire - fire the wait event
func (m *Mega) waitEventsFire() {
	m.waitEventsMu.Lock()
	if len(m.waitEvents) > 0 {
		m.debugf("Signalling events received")
		for _, ch := range m.waitEvents {
			close(ch)
		}
		m.waitEvents = nil
	}
	m.waitEventsMu.Unlock()
}

func (m *Mega) removeWaitEvent(eventChan <-chan struct{}) {
	m.waitEventsMu.Lock()
	defer m.waitEventsMu.Unlock()
	for i, ch := range m.waitEvents {
		if ch == eventChan {
			m.waitEvents = append(m.waitEvents[:i], m.waitEvents[i+1:]...)
			return
		}
	}
}

// Get user information
func (m *Mega) GetUser() (UserResp, error) {
	return m.GetUserContext(context.Background())
}

// GetUserContext fetches user information using ctx.
func (m *Mega) GetUserContext(ctx context.Context) (UserResp, error) {
	var msg [1]UserMsg
	var res [1]UserResp

	msg[0].Cmd = "ug"

	req, err := json.Marshal(msg)
	if err != nil {
		return res[0], err
	}
	result, err := m.api_request_context(ctx, req)
	if err != nil {
		return res[0], err
	}

	err = json.Unmarshal(result, &res)
	return res[0], err
}

// Get quota information
func (m *Mega) GetQuota() (QuotaResp, error) {
	return m.GetQuotaContext(context.Background())
}

// GetQuotaContext fetches quota information using ctx.
func (m *Mega) GetQuotaContext(ctx context.Context) (QuotaResp, error) {
	var msg [1]QuotaMsg
	var res [1]QuotaResp

	msg[0].Cmd = "uq"
	msg[0].Xfer = 1
	msg[0].Strg = 1

	req, err := json.Marshal(msg)
	if err != nil {
		return res[0], err
	}
	result, err := m.api_request_context(ctx, req)
	if err != nil {
		return res[0], err
	}

	err = json.Unmarshal(result, &res)
	return res[0], err
}

// Add a node into filesystem
func (m *Mega) addFSNode(itm FSNode) (*Node, error) {
	var compkey, key []uint32
	var attr FileAttr
	var node, parent *Node
	var err error
	if itm.Hash == "" {
		return nil, errors.New("filesystem node has no handle")
	}
	if itm.T < FILE || itm.T > TRASH {
		return nil, fmt.Errorf("filesystem node %q has unknown type %d", itm.Hash, itm.T)
	}

	master_aes, err := aes.NewCipher(m.k)
	if err != nil {
		return nil, err
	}

	switch {
	case itm.T == FOLDER || itm.T == FILE:
		args := strings.Split(itm.Key, ":")
		if len(args) < 2 {
			return nil, fmt.Errorf("not enough : in item.Key: %q", itm.Key)
		}
		itemUser, itemKey := args[0], args[1]
		itemKeyParts := strings.Split(itemKey, "/")
		if len(itemKeyParts) >= 2 {
			itemKey = itemKeyParts[0]
			// the other part is maybe a share key handle?
		}

		switch {
		// File or folder owned by current user
		case itemUser == itm.User:
			buf, err := base64urldecode(itemKey)
			if err != nil {
				return nil, err
			}
			err = blockDecrypt(master_aes, buf, buf)
			if err != nil {
				return nil, err
			}
			compkey, err = bytes_to_a32(buf)
			if err != nil {
				return nil, err
			}
			// Shared folder
		case itm.SUser != "" && itm.SKey != "":
			sk, err := base64urldecode(itm.SKey)
			if err != nil {
				return nil, err
			}
			err = blockDecrypt(master_aes, sk, sk)
			if err != nil {
				return nil, err
			}
			sk_aes, err := aes.NewCipher(sk)
			if err != nil {
				return nil, err
			}

			m.FS.skmap[itm.Hash] = itm.SKey
			buf, err := base64urldecode(itemKey)
			if err != nil {
				return nil, err
			}
			err = blockDecrypt(sk_aes, buf, buf)
			if err != nil {
				return nil, err
			}
			compkey, err = bytes_to_a32(buf)
			if err != nil {
				return nil, err
			}
			// Shared file
		default:
			k, ok := m.FS.skmap[itemUser]
			if !ok {
				return nil, errors.New("couldn't find decryption key for shared file")
			}
			b, err := base64urldecode(k)
			if err != nil {
				return nil, err
			}
			err = blockDecrypt(master_aes, b, b)
			if err != nil {
				return nil, err
			}
			block, err := aes.NewCipher(b)
			if err != nil {
				return nil, err
			}
			buf, err := base64urldecode(itemKey)
			if err != nil {
				return nil, err
			}
			err = blockDecrypt(block, buf, buf)
			if err != nil {
				return nil, err
			}
			compkey, err = bytes_to_a32(buf)
			if err != nil {
				return nil, err
			}
		}

		switch {
		case itm.T == FILE:
			if len(compkey) < 8 {
				return nil, fmt.Errorf("filesystem node %q has an incomplete file key", itm.Hash)
			}
			key = []uint32{compkey[0] ^ compkey[4], compkey[1] ^ compkey[5], compkey[2] ^ compkey[6], compkey[3] ^ compkey[7]}
		default:
			key = compkey
		}

		bkey, err := a32_to_bytes(key)
		if err != nil {
			return nil, err
		}
		attr, err = decryptAttr(bkey, itm.Attr)
		if err != nil {
			return nil, fmt.Errorf("filesystem node %q has an invalid encrypted attribute: %w", itm.Hash, err)
		}
	}

	n, ok := m.FS.lookup[itm.Hash]
	switch {
	case ok:
		node = n
	default:
		node = &Node{
			fs:    m.FS,
			ntype: itm.T,
			size:  itm.Sz,
			ts:    time.Unix(itm.Ts, 0),
		}

		m.FS.lookup[itm.Hash] = node
	}

	n, ok = m.FS.lookup[itm.Parent]
	switch {
	case ok:
		parent = n
		// Detach the node from its old parent if it is being
		// reparented so it doesn't appear in two directories.
		if node.parent != nil && node.parent != parent {
			node.parent.removeChild(node)
		}
		parent.removeChild(node)
		parent.addChild(node)
	default:
		parent = nil
		if itm.Parent != "" {
			parent = &Node{
				fs:       m.FS,
				children: []*Node{node},
				ntype:    FOLDER,
			}
			m.FS.lookup[itm.Parent] = parent
		}
	}

	switch {
	case itm.T == FILE:
		var meta NodeMeta
		meta.key, err = a32_to_bytes(key)
		if err != nil {
			return nil, err
		}
		meta.iv, err = a32_to_bytes([]uint32{compkey[4], compkey[5], 0, 0})
		if err != nil {
			return nil, err
		}
		meta.mac, err = a32_to_bytes([]uint32{compkey[6], compkey[7]})
		if err != nil {
			return nil, err
		}
		meta.compkey, err = a32_to_bytes(compkey)
		if err != nil {
			return nil, err
		}
		node.meta = meta
	case itm.T == FOLDER:
		var meta NodeMeta
		meta.key, err = a32_to_bytes(key)
		if err != nil {
			return nil, err
		}
		meta.compkey, err = a32_to_bytes(compkey)
		if err != nil {
			return nil, err
		}
		node.meta = meta
	case itm.T == ROOT:
		attr.Name = "Cloud Drive"
		m.FS.root = node
	case itm.T == INBOX:
		attr.Name = "InBox"
		m.FS.inbox = node
	case itm.T == TRASH:
		attr.Name = "Trash"
		m.FS.trash = node
	}

	// Shared directories
	if itm.SUser != "" && itm.SKey != "" {
		m.FS.sroots = append(m.FS.sroots, node)
	}

	node.name = attr.Name
	node.hash = itm.Hash
	node.parent = parent
	node.ntype = itm.T

	return node, nil
}

// Get all nodes from filesystem
func (m *Mega) getFileSystem() error {
	return m.getFileSystemContext(context.Background())
}

func (m *Mega) getFileSystemContext(ctx context.Context) error {
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	var msg [1]FilesMsg
	var res [1]FilesResp

	msg[0].Cmd = "f"
	msg[0].C = 1

	req, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	result, err := m.api_request_context(ctx, req)
	if err != nil {
		return err
	}

	err = json.Unmarshal(result, &res)
	if err != nil {
		return err
	}

	for _, sk := range res[0].Ok {
		m.FS.skmap[sk.Hash] = sk.Key
	}

	for _, itm := range res[0].F {
		_, err = m.addFSNode(itm)
		if err != nil {
			return fmt.Errorf("getFileSystem: invalid node %q: %w", itm.Hash, err)
		}
	}

	m.ssn = res[0].Sn

	m.startEventPoller()

	return nil
}

// Download contains the internal state of a download
type Download struct {
	m           *Mega
	src         *Node
	resourceUrl string
	aes_block   cipher.Block
	iv          []byte
	mac_enc     cipher.BlockMode
	mutex       sync.Mutex // to protect the following
	chunks      []chunkSize
	chunk_macs  [][]byte
}

// an all nil IV for mac calculations
var zero_iv = make([]byte, 16)

// Create a new Download from the src Node
//
// Call Chunks to find out how many chunks there are, then for id =
// 0..chunks-1 call DownloadChunk. Finally call Finish() to receive
// the error status.
func (m *Mega) NewDownload(src *Node) (*Download, error) {
	return m.NewDownloadContext(context.Background(), src)
}

// NewDownloadContext creates a download using ctx for its API request.
func (m *Mega) NewDownloadContext(ctx context.Context, src *Node) (*Download, error) {
	if src == nil {
		return nil, EARGS
	}

	var msg [1]DownloadMsg
	var res [1]DownloadResp

	m.FS.mutex.Lock()
	msg[0].Cmd = "g"
	msg[0].G = 1
	msg[0].N = src.hash
	if m.config.https {
		msg[0].SSL = 2
	}
	key := src.meta.key
	m.FS.mutex.Unlock()

	request, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	result, err := m.api_request_context(ctx, request)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(result, &res)
	if err != nil {
		return nil, err
	}

	// DownloadResp has an embedded error in it for some reason
	if res[0].Err != 0 {
		return nil, parseError(res[0].Err)
	}

	_, err = decryptAttr(key, res[0].Attr)
	if err != nil {
		return nil, err
	}

	chunks := getChunkSizes(int64(res[0].Size))

	aes_block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mac_enc := cipher.NewCBCEncrypter(aes_block, zero_iv)
	m.FS.mutex.Lock()
	t, err := bytes_to_a32(src.meta.iv)
	m.FS.mutex.Unlock()
	if err != nil {
		return nil, err
	}
	iv, err := a32_to_bytes([]uint32{t[0], t[1], t[0], t[1]})
	if err != nil {
		return nil, err
	}

	downloadUrl := res[0].G
	if m.config.https && strings.HasPrefix(downloadUrl, "http://") {
		downloadUrl = "https://" + strings.TrimPrefix(downloadUrl, "http://")
	}

	d := &Download{
		m:           m,
		src:         src,
		resourceUrl: downloadUrl,
		aes_block:   aes_block,
		iv:          iv,
		mac_enc:     mac_enc,
		chunks:      chunks,
		chunk_macs:  make([][]byte, len(chunks)),
	}
	return d, nil
}

// Chunks returns The number of chunks in the download.
func (d *Download) Chunks() int {
	return len(d.chunks)
}

// ChunkLocation returns the position in the file and the size of the chunk
func (d *Download) ChunkLocation(id int) (position int64, size int, err error) {
	if id < 0 || id >= len(d.chunks) {
		return 0, 0, EARGS
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.chunks[id].position, d.chunks[id].size, nil
}

// DownloadChunk gets a chunk with the given number and update the
// mac, returning the position in the file of the chunk
func (d *Download) DownloadChunk(id int) (chunk []byte, err error) {
	return d.DownloadChunkContext(context.Background(), id)
}

// DownloadChunkContext downloads and decrypts one chunk using ctx.
func (d *Download) DownloadChunkContext(ctx context.Context, id int) (chunk []byte, err error) {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if id < 0 || id >= len(d.chunks) {
		return nil, EARGS
	}

	chk_start, chk_size, err := d.ChunkLocation(id)
	if err != nil {
		return nil, err
	}

	var resp *http.Response
	chunk_url := fmt.Sprintf("%s/%d-%d", d.resourceUrl, chk_start, chk_start+int64(chk_size)-1)
	sleepTime := minSleepTime // initial backoff time
	for retry := 0; retry < d.m.retries+1; retry++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, chunk_url, nil)
		if err != nil {
			return nil, err
		}
		resp, err = d.m.client.Do(req)
		if err == nil {
			if resp != nil && resp.StatusCode == http.StatusOK {
				break
			}
			if resp == nil {
				err = errors.New("HTTP client returned a nil response")
			} else {
				err = errors.New("Http Status: " + resp.Status)
				closeAPIResponse(resp)
			}
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		err = sanitizeAPIError(err, chunk_url)
		d.m.debugf("%s: Retry download chunk %d/%d: %v", d.src.name, retry, d.m.retries, err)
		if retry+1 < d.m.retries+1 {
			if err := sleepContext(ctx, sleepTime); err != nil {
				return nil, err
			}
			advanceBackoff(&sleepTime)
		}
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("retries exceeded")
	}
	if resp.Body == nil {
		return nil, errors.New("HTTP response body is nil")
	}

	chunk, err = io.ReadAll(resp.Body)
	if err != nil {
		_ = resp.Body.Close()
		return nil, err
	}

	err = resp.Body.Close()
	if err != nil {
		return nil, err
	}

	// body is read and closed here

	if len(chunk) != chk_size {
		return nil, errors.New("wrong size for downloaded chunk")
	}

	// Decrypt the block
	ctr_iv, err := bytes_to_a32(d.src.meta.iv)
	if err != nil {
		return nil, err
	}
	ctr_iv[2] = uint32(uint64(chk_start) / 0x1000000000)
	ctr_iv[3] = uint32(chk_start / 0x10)
	bctr_iv, err := a32_to_bytes(ctr_iv)
	if err != nil {
		return nil, err
	}
	ctr_aes := cipher.NewCTR(d.aes_block, bctr_iv)
	ctr_aes.XORKeyStream(chunk, chunk)

	// Update the chunk_macs
	enc := cipher.NewCBCEncrypter(d.aes_block, d.iv)
	i := 0
	block := make([]byte, 16)
	paddedChunk := paddnull(chunk, 16)
	for i = 0; i < len(paddedChunk); i += 16 {
		enc.CryptBlocks(block, paddedChunk[i:i+16])
	}

	d.mutex.Lock()
	if len(d.chunk_macs) > 0 {
		d.chunk_macs[id] = make([]byte, 16)
		copy(d.chunk_macs[id], block)
	}
	d.mutex.Unlock()

	return chunk, nil
}

// Finish checks the accumulated MAC for each block.
//
// If all the chunks weren't downloaded then it will just return nil
func (d *Download) Finish() error {
	return d.FinishContext(context.Background())
}

// FinishContext verifies the downloaded file MAC and stops promptly when ctx
// is canceled. It does not perform network requests.
func (d *Download) FinishContext(ctx context.Context) error {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	// Can't check a 0 sized file
	if len(d.chunk_macs) == 0 {
		return nil
	}
	mac_data := make([]byte, 16)
	var macEnc cipher.BlockMode
	for _, v := range d.chunk_macs {
		if err := ctx.Err(); err != nil {
			return err
		}
		// If a chunk_macs hasn't been set then the whole file
		// wasn't downloaded and we can't check it
		if v == nil {
			return nil
		}
		if macEnc == nil {
			if d.aes_block == nil {
				return errors.New("download cipher is not initialized")
			}
			macEnc = cipher.NewCBCEncrypter(d.aes_block, zero_iv)
		}
		macEnc.CryptBlocks(mac_data, v)
	}

	tmac, err := bytes_to_a32(mac_data)
	if err != nil {
		return err
	}
	btmac, err := a32_to_bytes([]uint32{tmac[0] ^ tmac[1], tmac[2] ^ tmac[3]})
	if err != nil {
		return err
	}
	if !bytes.Equal(btmac, d.src.meta.mac) {
		return EMACMISMATCH
	}

	return nil
}

// Download file from filesystem reporting progress if not nil
func (m *Mega) DownloadFile(src *Node, dstpath string, progress *chan int) error {
	return m.DownloadFileContext(context.Background(), src, dstpath, progress)
}

// DownloadFileContext downloads a file and cancels outstanding chunk requests
// when ctx is canceled or any worker fails.
func (m *Mega) DownloadFileContext(ctx context.Context, src *Node, dstpath string, progress *chan int) error {
	defer func() {
		if progress != nil {
			close(*progress)
		}
	}()
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}

	d, err := m.NewDownloadContext(ctx, src)
	if err != nil {
		return err
	}
	return downloadToPathContext(ctx, d, dstpath, progress)
}

// downloadToPathContext stages a complete, MAC-verified download beside the
// destination and replaces the destination only after every check succeeds.
func downloadToPathContext(ctx context.Context, d *Download, dstpath string, progress *chan int) error {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if dstpath == "" {
		return os.ErrInvalid
	}
	if d == nil {
		return errors.New("download is not initialized")
	}
	if d.Chunks() > 0 && d.m == nil {
		return errors.New("download client is not initialized")
	}
	workers := 0
	if d.m != nil {
		workers = d.m.dl_workers
	}
	if d.Chunks() > 0 && workers <= 0 {
		return EWORKER_COUNT_INVALID
	}

	destInfo, err := os.Lstat(dstpath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if destInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("download destination is a symlink")
		}
		if !destInfo.Mode().IsRegular() {
			return errors.New("download destination is not a regular file")
		}
	}

	outfile, err := os.CreateTemp(filepath.Dir(dstpath), ".mega-download-*.partial")
	if err != nil {
		return err
	}
	tempPath := outfile.Name()
	defer func() {
		_ = outfile.Close()
		_ = os.Remove(tempPath)
	}()

	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	workch := make(chan int)
	errch := make(chan error, workers)
	wg := sync.WaitGroup{}
	reportErr := func(err error) {
		select {
		case errch <- err:
		default:
		}
		cancel()
	}

	// Fire chunk download workers
	for w := 0; w < workers; w++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			// Wait for work blocked on channel
			for id := range workch {
				if workCtx.Err() != nil {
					return
				}
				chunk, err := d.DownloadChunkContext(workCtx, id)
				if err != nil {
					reportErr(err)
					return
				}

				chk_start, _, err := d.ChunkLocation(id)
				if err != nil {
					reportErr(err)
					return
				}

				written, writeErr := outfile.WriteAt(chunk, chk_start)
				err = writeErr
				if err == nil && written != len(chunk) {
					err = io.ErrShortWrite
				}
				if err != nil {
					reportErr(err)
					return
				}

				if progress != nil {
					select {
					case *progress <- len(chunk):
					case <-workCtx.Done():
						return
					}
				}
			}
		}()
	}

	// Place chunk download jobs to chan
	err = nil
	for id := 0; id < d.Chunks() && err == nil; {
		select {
		case <-workCtx.Done():
			select {
			case err = <-errch:
			default:
				err = workCtx.Err()
			}
		case workch <- id:
			id++
		case err = <-errch:
		}
	}
	close(workch)

	wg.Wait()
	err = collectWorkerErrors(err, errch)
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}

	if err == nil && destInfo != nil {
		err = outfile.Chmod(destInfo.Mode().Perm())
	}
	if err == nil {
		err = outfile.Sync()
	}
	closeErr := outfile.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := d.FinishContext(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Rename(tempPath, dstpath)
}

func collectWorkerErrors(primary error, errch <-chan error) error {
	var firstWorkerErr error
	var uncertainWorkerErr error
	for {
		select {
		case workerErr := <-errch:
			if workerErr != nil {
				if firstWorkerErr == nil {
					firstWorkerErr = workerErr
				}
				if uncertainWorkerErr == nil && errors.Is(workerErr, ErrOutcomeUnknown) {
					uncertainWorkerErr = workerErr
				}
			}
		default:
			if uncertainWorkerErr != nil {
				return uncertainWorkerErr
			}
			if primary != nil {
				return primary
			}
			return firstWorkerErr
		}
	}
}

// Upload contains the internal state of a upload
type Upload struct {
	m                 *Mega
	parenthash        string
	name              string
	uploadUrl         string
	aes_block         cipher.Block
	iv                []byte
	kiv               []byte
	mac_enc           cipher.BlockMode
	kbytes            []byte
	ukey              []uint32
	mutex             sync.Mutex // to protect the following
	chunks            []chunkSize
	chunk_macs        [][]byte
	completion_handle []byte
}

// Create a new Upload of name into parent of fileSize
//
// Call Chunks to find out how many chunks there are, then for id =
// 0..chunks-1 Call ChunkLocation then UploadChunk.  Finally call
// Finish() to receive the error status and the *Node.
func (m *Mega) NewUpload(parent *Node, name string, fileSize int64) (*Upload, error) {
	return m.NewUploadContext(context.Background(), parent, name, fileSize)
}

// NewUploadContext starts an upload using ctx for its API request.
func (m *Mega) NewUploadContext(ctx context.Context, parent *Node, name string, fileSize int64) (*Upload, error) {
	if parent == nil {
		return nil, EARGS
	}

	var msg [1]UploadMsg
	var res [1]UploadResp
	parenthash := parent.GetHash()

	msg[0].Cmd = "u"
	msg[0].S = fileSize
	if m.config.https {
		msg[0].SSL = 2
	}

	request, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	result, err := m.api_request_context(ctx, request)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(result, &res)
	if err != nil {
		return nil, err
	}

	ukey := []uint32{0, 0, 0, 0, 0, 0}
	for i := range ukey {
		ukey[i] = uint32(mrand.Int31())

	}

	kbytes, err := a32_to_bytes(ukey[:4])
	if err != nil {
		return nil, err
	}
	kiv, err := a32_to_bytes([]uint32{ukey[4], ukey[5], 0, 0})
	if err != nil {
		return nil, err
	}
	aes_block, err := aes.NewCipher(kbytes)
	if err != nil {
		return nil, err
	}

	mac_enc := cipher.NewCBCEncrypter(aes_block, zero_iv)
	iv, err := a32_to_bytes([]uint32{ukey[4], ukey[5], ukey[4], ukey[5]})
	if err != nil {
		return nil, err
	}

	chunks := getChunkSizes(fileSize)

	// File size is zero
	// Do one empty request to get the completion handle
	if len(chunks) == 0 {
		chunks = append(chunks, chunkSize{position: 0, size: 0})
	}

	uploadUrl := res[0].P
	if m.config.https && strings.HasPrefix(uploadUrl, "http://") {
		uploadUrl = "https://" + strings.TrimPrefix(uploadUrl, "http://")
	}

	u := &Upload{
		m:                 m,
		parenthash:        parenthash,
		name:              name,
		uploadUrl:         uploadUrl,
		aes_block:         aes_block,
		iv:                iv,
		kiv:               kiv,
		mac_enc:           mac_enc,
		kbytes:            kbytes,
		ukey:              ukey,
		chunks:            chunks,
		chunk_macs:        make([][]byte, len(chunks)),
		completion_handle: []byte{},
	}
	return u, nil
}

// Chunks returns The number of chunks in the upload.
func (u *Upload) Chunks() int {
	return len(u.chunks)
}

// ChunkLocation returns the position in the file and the size of the chunk
func (u *Upload) ChunkLocation(id int) (position int64, size int, err error) {
	if id < 0 || id >= len(u.chunks) {
		return 0, 0, EARGS
	}
	return u.chunks[id].position, u.chunks[id].size, nil
}

// UploadChunk uploads the chunk of id
func (u *Upload) UploadChunk(id int, chunk []byte) (err error) {
	return u.UploadChunkContext(context.Background(), id, chunk)
}

// UploadChunkContext uploads one chunk using ctx. Upload chunk POSTs are never
// replayed automatically because a transport failure can follow server acceptance.
func (u *Upload) UploadChunkContext(ctx context.Context, id int, chunk []byte) (err error) {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	chk_start, chk_size, err := u.ChunkLocation(id)
	if err != nil {
		return err
	}
	if len(chunk) != chk_size {
		return errors.New("upload chunk is wrong size")
	}
	ctr_iv, err := bytes_to_a32(u.kiv)
	if err != nil {
		return err
	}
	ctr_iv[2] = uint32(uint64(chk_start) / 0x1000000000)
	ctr_iv[3] = uint32(chk_start / 0x10)
	bctr_iv, err := a32_to_bytes(ctr_iv)
	if err != nil {
		return err
	}
	ctr_aes := cipher.NewCTR(u.aes_block, bctr_iv)

	enc := cipher.NewCBCEncrypter(u.aes_block, u.iv)

	i := 0
	block := make([]byte, 16)
	chunkCopy := append([]byte(nil), chunk...)
	paddedchunk := paddnull(chunkCopy, 16)
	for i = 0; i < len(paddedchunk); i += 16 {
		copy(block[0:16], paddedchunk[i:i+16])
		enc.CryptBlocks(block, block)
	}

	var rsp *http.Response
	var req *http.Request
	encryptedChunk := append([]byte(nil), chunkCopy...)
	ctr_aes.XORKeyStream(encryptedChunk, encryptedChunk)
	chk_url := fmt.Sprintf("%s/%d", u.uploadUrl, chk_start)
	if err := ctx.Err(); err != nil {
		return err
	}
	reader := bytes.NewBuffer(encryptedChunk)
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, chk_url, reader)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rsp, err = u.m.client.Do(req)
	if err != nil {
		closeAPIResponse(rsp)
		return uncertainOutcomeError("upload chunk", sanitizeAPIError(err, chk_url))
	}
	if rsp == nil {
		return uncertainOutcomeError("upload chunk", errors.New("HTTP client returned a nil response"))
	}
	if rsp.StatusCode != http.StatusOK {
		statusErr := errors.New("Http Status: " + rsp.Status)
		closeAPIResponse(rsp)
		return uncertainOutcomeError("upload chunk", statusErr)
	}
	if rsp.Body == nil {
		return uncertainOutcomeError("upload chunk", errors.New("HTTP response body is nil"))
	}
	if ctx.Err() != nil {
		return uncertainOutcomeError("upload chunk", ctx.Err())
	}

	chunk_resp, err := io.ReadAll(rsp.Body)
	if err != nil {
		_ = rsp.Body.Close()
		return uncertainOutcomeError("upload chunk", sanitizeAPIError(err, chk_url))
	}

	err = rsp.Body.Close()
	if err != nil {
		return uncertainOutcomeError("upload chunk", sanitizeAPIError(err, chk_url))
	}

	if !bytes.Equal(chunk_resp, nil) {
		u.mutex.Lock()
		u.completion_handle = chunk_resp
		u.mutex.Unlock()
	}

	// Update chunk MACs on success only
	u.mutex.Lock()
	if len(u.chunk_macs) > 0 {
		u.chunk_macs[id] = make([]byte, 16)
		copy(u.chunk_macs[id], block)
	}
	u.mutex.Unlock()

	return nil
}

// Finish completes the upload and returns the created node
func (u *Upload) Finish() (node *Node, err error) {
	return u.FinishContext(context.Background())
}

// FinishContext finalizes an upload using ctx.
func (u *Upload) FinishContext(ctx context.Context) (node *Node, err error) {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mac_data := make([]byte, 16)
	var macEnc cipher.BlockMode
	for _, v := range u.chunk_macs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if v == nil {
			return nil, errors.New("upload chunk MAC is not initialized")
		}
		if macEnc == nil {
			if u.aes_block == nil {
				return nil, errors.New("upload cipher is not initialized")
			}
			macEnc = cipher.NewCBCEncrypter(u.aes_block, zero_iv)
		}
		macEnc.CryptBlocks(mac_data, v)
	}

	t, err := bytes_to_a32(mac_data)
	if err != nil {
		return nil, err
	}
	meta_mac := []uint32{t[0] ^ t[1], t[2] ^ t[3]}

	attr := FileAttr{u.name}

	attr_data, err := encryptAttr(u.kbytes, attr)
	if err != nil {
		return nil, err
	}

	key := []uint32{u.ukey[0] ^ u.ukey[4], u.ukey[1] ^ u.ukey[5],
		u.ukey[2] ^ meta_mac[0], u.ukey[3] ^ meta_mac[1],
		u.ukey[4], u.ukey[5], meta_mac[0], meta_mac[1]}

	buf, err := a32_to_bytes(key)
	if err != nil {
		return nil, err
	}
	master_aes, err := aes.NewCipher(u.m.k)
	if err != nil {
		return nil, err
	}
	enc := cipher.NewCBCEncrypter(master_aes, zero_iv)
	enc.CryptBlocks(buf[:16], buf[:16])
	enc = cipher.NewCBCEncrypter(master_aes, zero_iv)
	enc.CryptBlocks(buf[16:], buf[16:])

	var cmsg [1]UploadCompleteMsg
	var cres [1]UploadCompleteResp

	cmsg[0].Cmd = "p"
	cmsg[0].T = u.parenthash
	cmsg[0].N[0].H = string(u.completion_handle)
	cmsg[0].N[0].T = FILE
	cmsg[0].N[0].A = attr_data
	cmsg[0].N[0].K = base64urlencode(buf)

	request, err := json.Marshal(cmsg)
	if err != nil {
		return nil, err
	}
	result, err := u.m.api_request_context(ctx, request)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(result, &cres)
	if err != nil {
		return nil, uncertainOutcomeError("p", err)
	}
	if len(cres[0].F) == 0 {
		return nil, uncertainOutcomeError("p", EBADRESP)
	}

	u.m.FS.mutex.Lock()
	defer u.m.FS.mutex.Unlock()
	node, err = u.m.addFSNode(cres[0].F[0])
	if err != nil {
		return nil, uncertainOutcomeError("p", err)
	}
	if node == nil {
		return nil, uncertainOutcomeError("p", EBADRESP)
	}
	return node, nil
}

// Upload a file to the filesystem
func (m *Mega) UploadFile(srcpath string, parent *Node, name string, progress *chan int) (node *Node, err error) {
	return m.UploadFileContext(context.Background(), srcpath, parent, name, progress)
}

// UploadFileContext uploads a file and cancels outstanding work when ctx is
// canceled or any worker fails. An interrupted chunk upload reports an
// uncertain outcome and is never replayed automatically.
func (m *Mega) UploadFileContext(ctx context.Context, srcpath string, parent *Node, name string, progress *chan int) (node *Node, err error) {
	defer func() {
		if progress != nil {
			close(*progress)
		}
	}()
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.ul_workers <= 0 {
		return nil, EWORKER_COUNT_INVALID
	}

	var infile *os.File
	var fileSize int64

	info, err := os.Stat(srcpath)
	if err == nil {
		fileSize = info.Size()
	}

	infile, err = os.OpenFile(srcpath, os.O_RDONLY, 0666)
	if err != nil {
		return nil, err
	}
	defer func() {
		e := infile.Close()
		if err == nil {
			err = e
		}
	}()

	if name == "" {
		name = filepath.Base(srcpath)
	}

	u, err := m.NewUploadContext(ctx, parent, name, fileSize)
	if err != nil {
		return nil, err
	}

	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	workch := make(chan int)
	errch := make(chan error, m.ul_workers)
	wg := sync.WaitGroup{}
	reportErr := func(err error) {
		select {
		case errch <- err:
		default:
		}
		cancel()
	}

	// Fire chunk upload workers
	for w := 0; w < m.ul_workers; w++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for id := range workch {
				if workCtx.Err() != nil {
					return
				}
				chk_start, chk_size, err := u.ChunkLocation(id)
				if err != nil {
					reportErr(err)
					return
				}
				chunk := make([]byte, chk_size)
				n, err := infile.ReadAt(chunk, chk_start)
				if err != nil && err != io.EOF {
					reportErr(err)
					return
				}
				if n != len(chunk) {
					reportErr(errors.New("chunk too short"))
					return
				}

				err = u.UploadChunkContext(workCtx, id, chunk)
				if err != nil {
					reportErr(err)
					return
				}

				if progress != nil {
					select {
					case *progress <- chk_size:
					case <-workCtx.Done():
						return
					}
				}
			}
		}()
	}

	// Place chunk download jobs to chan
	err = nil
	for id := 0; id < u.Chunks() && err == nil; {
		select {
		case <-workCtx.Done():
			select {
			case err = <-errch:
			default:
				err = workCtx.Err()
			}
		case workch <- id:
			id++
		case err = <-errch:
		}
	}

	close(workch)

	wg.Wait()
	err = collectWorkerErrors(err, errch)
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}

	if err != nil {
		return nil, err
	}

	return u.FinishContext(ctx)
}

// Move a file from one location to another
func (m *Mega) Move(src *Node, parent *Node) error {
	return m.MoveContext(context.Background(), src, parent)
}

// MoveContext moves a node using ctx for the API request.
func (m *Mega) MoveContext(ctx context.Context, src *Node, parent *Node) error {
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	if src == nil || parent == nil {
		return EARGS
	}
	var msg [1]MoveFileMsg
	var err error

	msg[0].Cmd = "m"
	msg[0].N = src.hash
	msg[0].T = parent.hash
	msg[0].I, err = randString(10)
	if err != nil {
		return err
	}

	request, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = m.api_request_context(ctx, request)
	if err != nil {
		return err
	}

	if src.parent != nil {
		src.parent.removeChild(src)
	}

	parent.addChild(src)
	src.parent = parent

	return nil
}

// Rename a file or folder
func (m *Mega) Rename(src *Node, name string) error {
	return m.RenameContext(context.Background(), src, name)
}

// RenameContext renames a node using ctx for the API request.
func (m *Mega) RenameContext(ctx context.Context, src *Node, name string) error {
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	if src == nil {
		return EARGS
	}
	var msg [1]FileAttrMsg

	master_aes, err := aes.NewCipher(m.k)
	if err != nil {
		return err
	}
	attr := FileAttr{name}
	attr_data, err := encryptAttr(src.meta.key, attr)
	if err != nil {
		return err
	}
	key := make([]byte, len(src.meta.compkey))
	err = blockEncrypt(master_aes, key, src.meta.compkey)
	if err != nil {
		return err
	}

	msg[0].Cmd = "a"
	msg[0].Attr = attr_data
	msg[0].Key = base64urlencode(key)
	msg[0].N = src.hash
	msg[0].I, err = randString(10)
	if err != nil {
		return err
	}

	req, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = m.api_request_context(ctx, req)
	if err != nil {
		return err
	}

	src.name = name

	return nil
}

// Create a directory in the filesystem
func (m *Mega) CreateDir(name string, parent *Node) (*Node, error) {
	return m.CreateDirContext(context.Background(), name, parent)
}

// CreateDirContext creates a directory using ctx for the API request.
func (m *Mega) CreateDirContext(ctx context.Context, name string, parent *Node) (*Node, error) {
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	if parent == nil {
		return nil, EARGS
	}
	var msg [1]UploadCompleteMsg
	var res [1]UploadCompleteResp

	compkey := []uint32{0, 0, 0, 0, 0, 0}
	for i := range compkey {
		compkey[i] = uint32(mrand.Int31())
	}

	master_aes, err := aes.NewCipher(m.k)
	if err != nil {
		return nil, err
	}
	attr := FileAttr{name}
	ukey, err := a32_to_bytes(compkey[:4])
	if err != nil {
		return nil, err
	}
	attr_data, err := encryptAttr(ukey, attr)
	if err != nil {
		return nil, err
	}
	key := make([]byte, len(ukey))
	err = blockEncrypt(master_aes, key, ukey)
	if err != nil {
		return nil, err
	}

	msg[0].Cmd = "p"
	msg[0].T = parent.hash
	msg[0].N[0].H = "xxxxxxxx"
	msg[0].N[0].T = FOLDER
	msg[0].N[0].A = attr_data
	msg[0].N[0].K = base64urlencode(key)
	msg[0].I, err = randString(10)
	if err != nil {
		return nil, err
	}

	req, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	result, err := m.api_request_context(ctx, req)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(result, &res)
	if err != nil {
		return nil, uncertainOutcomeError("p", err)
	}
	if len(res[0].F) == 0 {
		return nil, uncertainOutcomeError("p", EBADRESP)
	}
	node, err := m.addFSNode(res[0].F[0])
	if err != nil {
		return nil, uncertainOutcomeError("p", err)
	}
	if node == nil {
		return nil, uncertainOutcomeError("p", EBADRESP)
	}

	return node, nil
}

// Delete a file or directory from filesystem
func (m *Mega) Delete(node *Node, destroy bool) error {
	return m.DeleteContext(context.Background(), node, destroy)
}

// DeleteContext deletes or trashes a node using ctx for its API request.
func (m *Mega) DeleteContext(ctx context.Context, node *Node, destroy bool) error {
	if node == nil {
		return EARGS
	}
	if !destroy {
		return m.MoveContext(ctx, node, m.FS.trash)
	}

	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	var msg [1]FileDeleteMsg
	var err error
	msg[0].Cmd = "d"
	msg[0].N = node.hash
	msg[0].I, err = randString(10)
	if err != nil {
		return err
	}

	req, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = m.api_request_context(ctx, req)
	if err != nil {
		return err
	}

	if node.parent != nil {
		node.parent.removeChild(node)
	}
	delete(m.FS.lookup, node.hash)

	return nil
}

// process an add node event
func (m *Mega) processAddNode(evRaw []byte) error {
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	var ev FSEvent
	err := json.Unmarshal(evRaw, &ev)
	if err != nil {
		return err
	}

	for _, itm := range ev.T.Files {
		_, err = m.addFSNode(itm)
		if err != nil {
			return err
		}
	}
	return nil
}

// process an update node event
func (m *Mega) processUpdateNode(evRaw []byte) error {
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	var ev FSEvent
	err := json.Unmarshal(evRaw, &ev)
	if err != nil {
		return err
	}

	node := m.FS.hashLookup(ev.N)
	if node == nil {
		return ENOENT
	}
	attr, err := decryptAttr(node.meta.key, ev.Attr)
	if err == nil {
		node.name = attr.Name
	} else {
		node.name = "BAD ATTRIBUTE"
	}

	node.ts = time.Unix(ev.Ts, 0)
	return nil
}

// process a delete node event
func (m *Mega) processDeleteNode(evRaw []byte) error {
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	var ev FSEvent
	err := json.Unmarshal(evRaw, &ev)
	if err != nil {
		return err
	}

	node := m.FS.hashLookup(ev.N)
	if node != nil && node.parent != nil {
		node.parent.removeChild(node)
		// A delete event which is part of a move (m is set) will be
		// followed by an add node event re-attaching the node, so keep
		// it in the lookup map to preserve the node's identity.
		if ev.Moved == 0 {
			delete(m.FS.lookup, node.hash)
		}
	}
	return nil
}

// Listen for server event notifications and play actions
func (m *Mega) pollEvents(ctx context.Context) {
	var err error
	var resp *http.Response
	sleepTime := minSleepTime // initial backoff time
	for {
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			m.debugf("pollEvents: error from server: %v", sanitizeAPIError(err, m.sid))
			if sleepContext(ctx, sleepTime) != nil {
				return
			}
			advanceBackoff(&sleepTime)
		} else {
			// reset sleep time to minimum on success
			sleepTime = minSleepTime
		}

		url := fmt.Sprintf("%s/sc?sn=%s&sid=%s", m.baseurl, m.ssn, m.sid)
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
		if err == nil {
			req.Header.Set("Content-Type", "application/xml")
			resp, err = m.client.Do(req)
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			m.logf("pollEvents: Error fetching status: %s", sanitizeAPIError(err, m.sid))
			continue
		}
		if resp == nil {
			err = errors.New("HTTP client returned a nil response")
			continue
		}

		if resp.StatusCode != 200 {
			m.logf("pollEvents: Error from server: %s", resp.Status)
			closeAPIResponse(resp)
			continue
		}
		if resp.Body == nil {
			err = errors.New("HTTP response body is nil")
			continue
		}

		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			m.logf("pollEvents: Error reading body: %v", err)
			_ = resp.Body.Close()
			continue
		}
		err = resp.Body.Close()
		if err != nil {
			m.logf("pollEvents: Error closing body: %v", err)
			continue
		}

		// body is read and closed here

		// First attempt to parse an array
		var events Events
		err = json.Unmarshal(buf, &events)
		if err != nil {
			// Try parsing as a lone error message
			var emsg ErrorMsg
			err = json.Unmarshal(buf, &emsg)
			if err != nil {
				m.logf("pollEvents: Bad response received from server: %s", buf)
			} else {
				err = parseError(emsg)
				if err == EAGAIN {
				} else if err != nil {
					m.logf("pollEvents: Error received from server: %v", err)
				}
			}
			continue
		}

		// if wait URL is set, then fetch it and continue - we
		// don't expect anything else if we have a wait URL.
		if events.W != "" {
			m.waitEventsFire()
			if len(events.E) > 0 {
				m.logf("pollEvents: Unexpected event with w set: %s", buf)
			}
			var waitReq *http.Request
			waitReq, err = http.NewRequestWithContext(ctx, http.MethodGet, events.W, nil)
			if err == nil {
				resp, err = m.client.Do(waitReq)
			}
			if err == nil && resp != nil {
				closeAPIResponse(resp)
			} else if err == nil {
				err = errors.New("HTTP client returned a nil response")
			}
			if ctx.Err() != nil {
				return
			}
			continue
		}
		m.ssn = events.Sn

		// For each event in the array, parse it
		for _, evRaw := range events.E {
			if ctx.Err() != nil {
				return
			}
			// First attempt to unmarshal as an error message
			var emsg ErrorMsg
			err = json.Unmarshal(evRaw, &emsg)
			if err == nil {
				m.logf("pollEvents: Error message received %s", evRaw)
				err = parseError(emsg)
				if err != nil {
					m.logf("pollEvents: Event from server was error: %v", err)
				}
				continue
			}

			// Now unmarshal as a generic event
			var gev GenericEvent
			err = json.Unmarshal(evRaw, &gev)
			if err != nil {
				m.logf("pollEvents: Couldn't parse event from server: %v: %s", err, evRaw)
				continue
			}
			m.debugf("pollEvents: Parsing event %q: %s", gev.Cmd, evRaw)

			// Work out what to do with the event
			var process func([]byte) error
			switch gev.Cmd {
			case "t": // node addition
				process = m.processAddNode
			case "u": // node update
				process = m.processUpdateNode
			case "d": // node deletion
				process = m.processDeleteNode
			case "s", "s2": // share addition/update/revocation
			case "c": // contact addition/update
			case "k": // crypto key request
			case "fa": // file attribute update
			case "ua": // user attribute update
			case "psts": // account updated
			case "ipc": // incoming pending contact request (to us)
			case "opc": // outgoing pending contact request (from us)
			case "upci": // incoming pending contact request update (accept/deny/ignore)
			case "upco": // outgoing pending contact request update (from them, accept/deny/ignore)
			case "ph": // public links handles
			case "se": // set email
			case "mcc": // chat creation / peer's invitation / peer's removal
			case "mcna": // granted / revoked access to a node
			case "uac": // user access control
			default:
				m.debugf("pollEvents: Unknown message %q received: %s", gev.Cmd, evRaw)
			}

			// process the event if we can
			if process != nil {
				err := process(evRaw)
				if err != nil {
					m.logf("pollEvents: Error processing event %q '%s': %v", gev.Cmd, evRaw, err)
				}
			}
		}
	}
}

func (m *Mega) getLink(n *Node) (string, error) {
	return m.getLinkContext(context.Background(), n)
}

func (m *Mega) getLinkContext(ctx context.Context, n *Node) (string, error) {
	var msg [1]GetLinkMsg
	var res [1]string

	msg[0].Cmd = "l"
	msg[0].N = n.GetHash()

	req, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	result, err := m.api_request_context(ctx, req)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(result, &res)
	if err != nil {
		return "", err
	}
	return res[0], nil
}

// Exports public link for node, with or without decryption key included
func (m *Mega) Link(n *Node, includeKey bool) (string, error) {
	return m.LinkContext(context.Background(), n, includeKey)
}

// LinkContext exports a node link using ctx for the API request.
func (m *Mega) LinkContext(ctx context.Context, n *Node, includeKey bool) (string, error) {
	id, err := m.getLinkContext(ctx, n)
	if err != nil {
		return "", err
	}
	if includeKey {
		m.FS.mutex.Lock()
		key := base64urlencode(n.meta.compkey)
		m.FS.mutex.Unlock()
		return fmt.Sprintf("%v/#!%v!%v", BASE_DOWNLOAD_URL, id, key), nil
	} else {
		return fmt.Sprintf("%v/#!%v", BASE_DOWNLOAD_URL, id), nil
	}
}

// addRequestHeaders adds standard headers to a request
func addRequestHeaders(req *http.Request) {
	userAgent := os.Getenv("X_MEGA_USER_AGENT")
	if userAgent != "" || X_MEGA_USER_AGENT != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	req.Header.Set("Content-Type", "application/json")
}

// addHashCashRequestHeaders adds standard headers and hashcash headers to a request
func addHashCashRequestHeaders(req *http.Request, token string, cashValue string) {
	addRequestHeaders(req)
	if token != "" && cashValue != "" {
		req.Header.Set("X-Hashcash", fmt.Sprintf("1:%s:%s", token, cashValue))
	}
}

// getAPIBaseURL returns the base URL for API requests
func getAPIBaseURL() string {
	url := os.Getenv("X_MEGA_API_URL")
	if url == "" {
		return API_URL
	}
	return url
}
