package mega

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type filesystemPollerStart struct {
	call int
	sn   string
}

type sessionRequestObservation struct {
	path string
	sid  string
	sn   string
}

type observedDoneContext struct {
	context.Context
	once    sync.Once
	entered chan struct{}
}

type doneObservedAfterContext struct {
	context.Context
	after   <-chan struct{}
	once    sync.Once
	entered chan struct{}
}

type cancelAfterContextChecks struct {
	context.Context
	checksUntilCancel int
}

type closeTrackingReadCloser struct {
	io.Reader
	closed bool
}

type closeSignalReadCloser struct {
	io.Reader
	closed chan struct{}
	once   sync.Once
}

func (b *closeTrackingReadCloser) Close() error {
	b.closed = true
	return nil
}

func (b *closeSignalReadCloser) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func (c *cancelAfterContextChecks) Err() error {
	if c.checksUntilCancel == 0 {
		return context.Canceled
	}
	c.checksUntilCancel--
	return nil
}

func (c *observedDoneContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func (c *doneObservedAfterContext) Done() <-chan struct{} {
	select {
	case <-c.after:
		c.once.Do(func() { close(c.entered) })
	default:
	}
	return c.Context.Done()
}

func waitForGoroutineBlockedAtMutex(function string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	stack := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		n := runtime.Stack(stack, true)
		for _, goroutine := range bytes.Split(stack[:n], []byte("\n\n")) {
			if bytes.Contains(goroutine, []byte(function)) && bytes.Contains(goroutine, []byte("sync.(*Mutex).Lock")) {
				return true
			}
		}
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	return false
}

func waitForMutexHeldByAnother(mutex *sync.Mutex, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if mutex.TryLock() {
			mutex.Unlock()
		} else {
			return true
		}
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	return false
}

func TestAPIRequestContextCancellationInFlight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	}), 4)

	result := make(chan error, 1)
	go func() {
		_, err := m.api_request_context(ctx, []byte(`[{"a":"uq"}]`))
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("api_request_context() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("API request did not stop after cancellation")
	}
	if calls != 1 {
		t.Fatalf("transport calls = %d, want 1", calls)
	}
}

func TestAPIRequestMutationCanceledInFlightIsUnknownAndNotReplayed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	}), 4)

	result := make(chan error, 1)
	go func() {
		_, err := m.api_request_context(ctx, []byte(`[{"a":"d","n":"node"}]`))
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, context.Canceled) {
			t.Fatalf("api_request_context() error = %v, want unknown outcome and context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("mutating API request did not stop after cancellation")
	}
	if calls != 1 {
		t.Fatalf("transport calls = %d, want 1", calls)
	}
}

func TestAPIRequestContextCancellationWhileQueued(t *testing.T) {
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("transport called while the API gate is held")
		return nil, nil
	}), 1)
	release, err := m.acquireAPIGate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	parent, cancel := context.WithCancel(context.Background())
	ctx := &observedDoneContext{Context: parent, entered: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := m.api_request_context(ctx, []byte(`[{"a":"uq"}]`))
		result <- err
	}()
	select {
	case <-ctx.entered:
	case <-time.After(time.Second):
		t.Fatal("request did not begin waiting for the API gate")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("api_request_context() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued API request did not stop after cancellation")
	}
}

func TestAPIRequestContextCancellationDuringRetryBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	responded := make(chan struct{})
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		resp := apiTestResponse(http.StatusServiceUnavailable, "temporary")
		resp.Header.Set("Retry-After", "5")
		close(responded)
		return resp, nil
	}), 4)

	result := make(chan error, 1)
	go func() {
		_, err := m.api_request_context(ctx, []byte(`[{"a":"uq"}]`))
		result <- err
	}()
	<-responded
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("api_request_context() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("retry backoff did not stop after cancellation")
	}
	if calls != 1 {
		t.Fatalf("transport calls = %d, want 1", calls)
	}
}

func TestSleepContextStopsDuringBackoff(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	ctx := &observedDoneContext{Context: parent, entered: make(chan struct{})}
	result := make(chan error, 1)
	go func() { result <- sleepContext(ctx, time.Hour) }()
	select {
	case <-ctx.entered:
	case <-time.After(time.Second):
		t.Fatal("backoff timer did not begin")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("sleepContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("backoff timer did not stop after cancellation")
	}
}

func TestUploadChunkContextCancellationIsUnknownAndNotReplayed(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, aes.BlockSize))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	}), 5)
	u := &Upload{
		m:          m,
		name:       "sample",
		uploadUrl:  "https://mega.invalid/upload",
		aes_block:  block,
		iv:         make([]byte, aes.BlockSize),
		kiv:        make([]byte, aes.BlockSize),
		chunks:     []chunkSize{{position: 0, size: 1}},
		chunk_macs: make([][]byte, 1),
	}

	result := make(chan error, 1)
	go func() { result <- u.UploadChunkContext(ctx, 0, []byte{1}) }()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, context.Canceled) {
			t.Fatalf("UploadChunkContext() error = %v, want unknown outcome and context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upload chunk did not stop after cancellation")
	}
	if calls != 1 {
		t.Fatalf("transport calls = %d, want 1", calls)
	}
}

func TestUploadChunkContextDoesNotFollowRedirects(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, aes.BlockSize))
	if err != nil {
		t.Fatal(err)
	}
	for _, statusCode := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			calls := 0
			sharedRedirectCalls := 0
			sharedRedirectErr := errors.New("shared redirect policy")
			m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					resp := apiTestResponse(statusCode, "redirect")
					resp.Header.Set("Location", "https://mega.invalid/replayed-chunk")
					return resp, nil
				}
				return apiTestResponse(http.StatusOK, "accepted"), nil
			}), 2)
			m.client.CheckRedirect = func(*http.Request, []*http.Request) error {
				sharedRedirectCalls++
				return sharedRedirectErr
			}
			u := &Upload{
				m:          m,
				name:       "sample",
				uploadUrl:  "https://mega.invalid/upload",
				aes_block:  block,
				iv:         make([]byte, aes.BlockSize),
				kiv:        make([]byte, aes.BlockSize),
				chunks:     []chunkSize{{position: 0, size: 1}},
				chunk_macs: make([][]byte, 1),
			}

			err := u.UploadChunkContext(context.Background(), 0, []byte{1})
			if !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("UploadChunkContext() error = %v, want ErrOutcomeUnknown for redirect", err)
			}
			if calls != 1 {
				t.Fatalf("transport calls = %d, want 1 (redirect must not replay the chunk POST)", calls)
			}
			if sharedRedirectCalls != 0 {
				t.Fatalf("shared CheckRedirect calls during upload = %d, want 0", sharedRedirectCalls)
			}
			if err := m.client.CheckRedirect(&http.Request{}, nil); !errors.Is(err, sharedRedirectErr) {
				t.Fatalf("shared CheckRedirect after upload = %v, want its configured policy error", err)
			}
			if sharedRedirectCalls != 1 {
				t.Fatalf("shared CheckRedirect calls after direct policy check = %d, want 1", sharedRedirectCalls)
			}
		})
	}
}

func TestContextFilesystemSnapshotsCanCancelWhileWaitingForMutex(t *testing.T) {
	tests := []struct {
		name string
		call func(*Mega, *Node, context.Context) error
	}{
		{
			name: "download snapshot",
			call: func(m *Mega, n *Node, ctx context.Context) error {
				_, err := m.NewDownloadContext(ctx, n)
				return err
			},
		},
		{
			name: "upload parent hash",
			call: func(m *Mega, n *Node, ctx context.Context) error {
				_, err := m.NewUploadContext(ctx, n, "sample", 1)
				return err
			},
		},
		{
			name: "link node hash",
			call: func(m *Mega, n *Node, ctx context.Context) error {
				_, err := m.getLinkContext(ctx, n)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("unexpected API request while filesystem mutex is held")
				return nil, nil
			}), 1)
			n := &Node{fs: m.FS, hash: "node-handle", meta: NodeMeta{key: make([]byte, aes.BlockSize), iv: make([]byte, aes.BlockSize)}}
			m.FS.mutex.Lock()
			defer m.FS.mutex.Unlock()

			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &observedDoneContext{Context: parent, entered: make(chan struct{})}
			result := make(chan error, 1)
			go func() { result <- tt.call(m, n, ctx) }()
			select {
			case <-ctx.entered:
			case <-time.After(time.Second):
				t.Fatal("operation did not begin waiting for the filesystem mutex")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("operation error = %v, want context.Canceled", err)
				}
			case <-time.After(time.Second):
				t.Fatal("operation did not stop waiting after cancellation")
			}
		})
	}
}

func TestGetFileSystemContextCanCancelWhileWaitingForFilesystemMutex(t *testing.T) {
	responseBodyClosed := make(chan struct{})
	body := []byte(`[{"f":[{"h":"root","t":2}],"sn":"session-sequence"}]`)
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		resp := apiTestResponse(http.StatusOK, string(body))
		resp.Body = &closeSignalReadCloser{Reader: bytes.NewReader(body), closed: responseBodyClosed}
		return resp, nil
	}), 1)
	m.k = make([]byte, aes.BlockSize)
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &doneObservedAfterContext{Context: parent, after: responseBodyClosed, entered: make(chan struct{})}
	result := make(chan error, 1)
	go func() { result <- m.getFileSystemContext(ctx) }()
	select {
	case <-responseBodyClosed:
	case <-time.After(time.Second):
		t.Fatal("filesystem response was not consumed")
	}
	select {
	case <-ctx.entered:
	case <-time.After(time.Second):
		t.Fatal("filesystem refresh did not begin waiting for FS.mutex after its response")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("getFileSystemContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("filesystem refresh did not stop waiting after cancellation")
	}
}

func TestGetFileSystemContextMalformedSnapshotDoesNotMutateCacheAndRestartsPoller(t *testing.T) {
	masterKey, validNode := finalizedUploadNode(t)
	malformedNode := validNode
	malformedNode.Hash = "malformed-second-node"
	malformedNode.Attr = "not-an-encrypted-attribute"
	toWireNode := func(node FSNode) map[string]any {
		return map[string]any{
			"h":  node.Hash,
			"p":  node.Parent,
			"u":  node.User,
			"t":  node.T,
			"a":  node.Attr,
			"k":  node.Key,
			"ts": node.Ts,
			"s":  node.Sz,
		}
	}
	responseBody, err := json.Marshal([]map[string]any{{
		"f":  []map[string]any{toWireNode(validNode), toWireNode(malformedNode)},
		"ok": []map[string]string{{"h": "incoming-share", "k": "incoming-share-key"}},
		"sn": "new-sequence",
	}})
	if err != nil {
		t.Fatal(err)
	}

	pollerStarted := make(chan filesystemPollerStart, 4)
	var scMu sync.Mutex
	scCalls := 0
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/sc":
			scMu.Lock()
			scCalls++
			call := scCalls
			scMu.Unlock()
			pollerStarted <- filesystemPollerStart{call: call, sn: req.URL.Query().Get("sn")}
			<-req.Context().Done()
			return nil, req.Context().Err()
		case "/cs":
			return apiTestResponse(http.StatusOK, string(responseBody)), nil
		default:
			return nil, fmt.Errorf("unexpected request path %q", req.URL.Path)
		}
	}), 1)
	m.k = masterKey
	m.ssn = "old-sequence"
	sentinel := &Node{fs: m.FS, hash: "sentinel", name: "keep"}
	m.FS.mutex.Lock()
	m.FS.lookup[sentinel.hash] = sentinel
	m.FS.skmap["existing-share"] = "existing-share-key"
	m.FS.mutex.Unlock()
	t.Cleanup(func() { _ = m.Close() })

	m.startEventPoller()
	firstPoller, ok := receivePollerStart(t, pollerStarted)
	if !ok || firstPoller.call != 1 || firstPoller.sn != "old-sequence" {
		t.Fatalf("initial poller start = %+v, received=%v; want call 1 at old sequence", firstPoller, ok)
	}
	m.eventMu.Lock()
	oldPollerDone := m.eventDone
	m.eventMu.Unlock()
	if oldPollerDone == nil {
		t.Fatal("old session poller has no completion signal")
	}

	err = m.getFileSystemContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid encrypted attribute") {
		t.Fatalf("getFileSystemContext() error = %v, want invalid encrypted attribute", err)
	}
	select {
	case <-oldPollerDone:
	case <-time.After(time.Second):
		t.Fatal("old poller was not joined after the failed refresh")
	}
	secondPoller, ok := receivePollerStart(t, pollerStarted)
	if !ok || secondPoller.call != 2 || secondPoller.sn != "old-sequence" {
		t.Fatalf("restarted poller start = %+v, received=%v; want call 2 at unchanged old sequence", secondPoller, ok)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close() after poller restart: %v", err)
	}

	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()
	if got := m.FS.lookup[sentinel.hash]; got != sentinel {
		t.Fatalf("sentinel lookup pointer = %p, want unchanged pointer %p", got, sentinel)
	}
	if len(m.FS.lookup) != 1 {
		t.Fatalf("live lookup entries = %v, want only the preexisting sentinel", m.FS.lookup)
	}
	if _, ok := m.FS.skmap["incoming-share"]; ok {
		t.Fatal("response share key was applied despite malformed later node")
	}
	if got := m.FS.skmap["existing-share"]; got != "existing-share-key" {
		t.Fatalf("preexisting share key = %q, want unchanged value", got)
	}
	if m.ssn != "old-sequence" {
		t.Fatalf("server sequence = %q, want unchanged old sequence", m.ssn)
	}
}

func receivePollerStart(t *testing.T, starts <-chan filesystemPollerStart) (filesystemPollerStart, bool) {
	t.Helper()
	select {
	case start := <-starts:
		return start, true
	case <-time.After(time.Second):
		return filesystemPollerStart{}, false
	}
}

func TestGetFileSystemContextPreservesCachedNodePointerOnSuccess(t *testing.T) {
	masterKey, node := finalizedUploadNode(t)
	responseBody, err := json.Marshal([]map[string]any{{
		"f":  []map[string]any{filesystemAPIWireNode(node)},
		"sn": "refreshed-sequence",
	}})
	if err != nil {
		t.Fatal(err)
	}
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/cs":
			return apiTestResponse(http.StatusOK, string(responseBody)), nil
		case "/sc":
			<-req.Context().Done()
			return nil, req.Context().Err()
		default:
			return nil, fmt.Errorf("unexpected request path %q", req.URL.Path)
		}
	}), 1)
	m.k = masterKey
	cached := &Node{fs: m.FS, hash: node.Hash, name: "cached-before-refresh"}
	m.FS.mutex.Lock()
	m.FS.lookup[node.Hash] = cached
	m.FS.mutex.Unlock()
	t.Cleanup(func() { _ = m.Close() })

	if err := m.getFileSystemContext(context.Background()); err != nil {
		t.Fatalf("getFileSystemContext() error = %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close() after refresh: %v", err)
	}

	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()
	if got := m.FS.lookup[node.Hash]; got != cached {
		t.Fatalf("refreshed node pointer = %p, want existing cached pointer %p", got, cached)
	}
	if cached.name != "sample" {
		t.Fatalf("refreshed cached node name = %q, want %q", cached.name, "sample")
	}
	if m.ssn != "refreshed-sequence" {
		t.Fatalf("server sequence = %q, want refreshed sequence", m.ssn)
	}
}

func TestGetFileSystemContextRejectsIncompleteSnapshotWithoutMutation(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "empty nodes", body: `[{"f":[],"sn":"new-sequence"}]`},
		{name: "missing nodes", body: `[{"sn":"new-sequence"}]`},
		{name: "missing sequence", body: `[{"f":[{"h":"root","t":2}]}]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/cs" {
					return nil, fmt.Errorf("unexpected request path %q", req.URL.Path)
				}
				return apiTestResponse(http.StatusOK, tt.body), nil
			}), 1)
			m.k = make([]byte, aes.BlockSize)
			m.ssn = "old-sequence"
			cached := &Node{fs: m.FS, hash: "cached", name: "preserve me"}
			m.FS.lookup[cached.hash] = cached

			err := m.getFileSystemContext(context.Background())
			if !errors.Is(err, EBADRESP) {
				t.Fatalf("getFileSystemContext() error = %v, want EBADRESP", err)
			}
			if m.FS.lookup[cached.hash] != cached || len(m.FS.lookup) != 1 {
				t.Fatalf("filesystem lookup after rejected response = %v, want only cached node %p", m.FS.lookup, cached)
			}
			if m.ssn != "old-sequence" {
				t.Fatalf("server sequence after rejected response = %q, want old-sequence", m.ssn)
			}
		})
	}
}

func TestGetFileSystemContextPrunesOmittedNodesAndRebuildsSharedRoots(t *testing.T) {
	masterKey := make([]byte, aes.BlockSize)
	root := FSNode{Hash: "root", T: ROOT}
	sharedOmitted := finalizedUploadFolder(t, masterKey, "shared-omitted", "omitted share", root.Hash)
	sharedRetained := finalizedUploadFolder(t, masterKey, "shared-retained", "old share name", root.Hash)
	fileOmitted := finalizedUploadNodeForKey(t, masterKey, "file-omitted", "omitted file")
	fileOmitted.Parent = root.Hash
	fileRetained := finalizedUploadNodeForKey(t, masterKey, "file-retained", "old file name")
	fileRetained.Parent = root.Hash

	updatedShared := finalizedUploadFolder(t, masterKey, sharedRetained.Hash, "new share name", root.Hash)
	updatedFile := finalizedUploadNodeForKey(t, masterKey, fileRetained.Hash, "new file name")
	updatedFile.Parent = root.Hash
	updatedFile.Ts = 2
	updatedFile.Sz = 23
	newFile := finalizedUploadNodeForKey(t, masterKey, "file-new", "new file")
	newFile.Parent = root.Hash
	newFile.Sz = 7

	responseBody, err := json.Marshal([]map[string]any{{
		"f": []map[string]any{
			filesystemAPIWireNode(root),
			filesystemAPIWireNode(updatedShared),
			filesystemAPIWireNode(updatedFile),
			filesystemAPIWireNode(newFile),
		},
		"sn": "authoritative-sequence",
	}})
	if err != nil {
		t.Fatal(err)
	}
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/cs":
			return apiTestResponse(http.StatusOK, string(responseBody)), nil
		case "/sc":
			<-req.Context().Done()
			return nil, req.Context().Err()
		default:
			return nil, fmt.Errorf("unexpected request path %q", req.URL.Path)
		}
	}), 1)
	m.k = masterKey
	for _, node := range []FSNode{root, sharedOmitted, sharedRetained, fileOmitted, fileRetained} {
		if _, err := m.addFSNodeWithMasterKey(node, masterKey); err != nil {
			t.Fatalf("add initial node %q: %v", node.Hash, err)
		}
	}
	m.FS.skmap["omitted-share-key"] = "stale-key"
	retainedSharedPointer := m.FS.lookup[sharedRetained.Hash]
	retainedFilePointer := m.FS.lookup[fileRetained.Hash]
	t.Cleanup(func() { _ = m.Close() })

	if err := m.getFileSystemContext(context.Background()); err != nil {
		t.Fatalf("getFileSystemContext() error = %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close() after refresh: %v", err)
	}

	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()
	if m.FS.lookup[sharedOmitted.Hash] != nil || m.FS.lookup[fileOmitted.Hash] != nil {
		t.Fatal("nodes omitted from the authoritative response remain in the lookup")
	}
	if _, found := m.FS.skmap["omitted-share-key"]; found {
		t.Fatal("share keys omitted from the authoritative response remain in the cache")
	}
	if m.FS.lookup[sharedRetained.Hash] != retainedSharedPointer {
		t.Fatalf("retained shared node pointer = %p, want %p", m.FS.lookup[sharedRetained.Hash], retainedSharedPointer)
	}
	if m.FS.lookup[fileRetained.Hash] != retainedFilePointer {
		t.Fatalf("retained file node pointer = %p, want %p", m.FS.lookup[fileRetained.Hash], retainedFilePointer)
	}
	if got := retainedSharedPointer.name; got != "new share name" {
		t.Fatalf("retained shared node name = %q, want refreshed name", got)
	}
	if got := retainedFilePointer.name; got != "new file name" {
		t.Fatalf("retained file node name = %q, want refreshed name", got)
	}
	if retainedFilePointer.size != 23 || retainedFilePointer.ts.Unix() != 2 {
		t.Fatalf("retained file metadata = size %d, timestamp %d; want size 23 and timestamp 2", retainedFilePointer.size, retainedFilePointer.ts.Unix())
	}
	if m.FS.root != m.FS.lookup[root.Hash] {
		t.Fatal("root pointer does not refer to the rebuilt root node")
	}
	if len(m.FS.sroots) != 1 || m.FS.sroots[0] != retainedSharedPointer {
		t.Fatalf("shared roots = %v, want only retained node %p", m.FS.sroots, retainedSharedPointer)
	}
	if len(m.FS.root.children) != 3 {
		t.Fatalf("root children = %d, want retained share, retained file, and new file", len(m.FS.root.children))
	}
	if m.ssn != "authoritative-sequence" {
		t.Fatalf("server sequence = %q, want authoritative-sequence", m.ssn)
	}
}

func TestMegaFSGettersReturnDefensiveSlices(t *testing.T) {
	fs := newMegaFS()
	root := &Node{fs: fs, hash: "root"}
	child := &Node{fs: fs, hash: "child"}
	sharedRoot := &Node{fs: fs, hash: "shared-root"}
	fs.mutex.Lock()
	fs.lookup[root.hash] = root
	root.children = []*Node{child}
	fs.sroots = []*Node{sharedRoot}
	fs.mutex.Unlock()

	children, err := fs.GetChildren(root)
	if err != nil {
		t.Fatalf("GetChildren() error = %v", err)
	}
	children[0] = nil
	if got, err := fs.GetChildren(root); err != nil || len(got) != 1 || got[0] != child {
		t.Fatalf("GetChildren() after caller mutation = %v, %v; want original child", got, err)
	}

	sharedRoots := fs.GetSharedRoots()
	sharedRoots[0] = nil
	if got := fs.GetSharedRoots(); len(got) != 1 || got[0] != sharedRoot {
		t.Fatalf("GetSharedRoots() after caller mutation = %v, want original shared root", got)
	}
}

func TestLoginWithKeysWaitsForInFlightFilesystemRefreshBeforeSessionReplacement(t *testing.T) {
	masterKeyA, nodeA := finalizedUploadNode(t)
	masterKeyB := bytes.Repeat([]byte{0x42}, aes.BlockSize)
	nodeB := finalizedUploadNodeForKey(t, masterKeyB, "session-b-node", "session B file")
	responseBodyA, err := json.Marshal([]map[string]any{{
		"f":  []map[string]any{filesystemAPIWireNode(nodeA)},
		"ok": []map[string]string{{"h": "session-A-share", "k": "share-key-A"}},
		"sn": "sequence-A",
	}})
	if err != nil {
		t.Fatal(err)
	}
	responseBodyB, err := json.Marshal([]map[string]any{{
		"f":  []map[string]any{filesystemAPIWireNode(nodeB)},
		"ok": []map[string]string{{"h": "session-B-share", "k": "share-key-B"}},
		"sn": "sequence-B",
	}})
	if err != nil {
		t.Fatal(err)
	}

	aFilesystemStarted := make(chan struct{})
	bFilesystemStarted := make(chan struct{})
	releaseAResponse := make(chan struct{})
	initialAPollerStarted := make(chan struct{})
	pollerRequests := make(chan sessionRequestObservation, 16)
	var aFilesystemOnce, bFilesystemOnce, initialPollerOnce sync.Once
	var bPollerMu sync.Mutex
	bPollerCalls := 0
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		path := req.URL.Path
		sid := req.URL.Query().Get("sid")
		sn := req.URL.Query().Get("sn")
		switch path {
		case "/cs":
			switch sid {
			case "session-A":
				aFilesystemOnce.Do(func() { close(aFilesystemStarted) })
				<-releaseAResponse
				return apiTestResponse(http.StatusOK, string(responseBodyA)), nil
			case "session-B":
				bFilesystemOnce.Do(func() { close(bFilesystemStarted) })
				return apiTestResponse(http.StatusOK, string(responseBodyB)), nil
			default:
				return nil, fmt.Errorf("filesystem request used unexpected session %q", sid)
			}
		case "/sc":
			observation := sessionRequestObservation{path: path, sid: sid, sn: sn}
			select {
			case pollerRequests <- observation:
			default:
			}
			if sid == "session-A" {
				if sn == "initial-A-sequence" {
					initialPollerOnce.Do(func() { close(initialAPollerStarted) })
				}
				<-req.Context().Done()
				return nil, req.Context().Err()
			}
			if sid == "session-B" {
				bPollerMu.Lock()
				bPollerCalls++
				call := bPollerCalls
				bPollerMu.Unlock()
				if call == 1 {
					return apiTestResponse(http.StatusOK, `{"w":"https://mega.invalid/wait"}`), nil
				}
				<-req.Context().Done()
				return nil, req.Context().Err()
			}
			return nil, fmt.Errorf("event poll used unexpected session %q", sid)
		case "/wait":
			return apiTestResponse(http.StatusOK, ""), nil
		default:
			return nil, fmt.Errorf("unexpected request path %q", path)
		}
	}), 1)
	m.sid = "session-A"
	m.k = append([]byte(nil), masterKeyA...)
	m.ssn = "initial-A-sequence"
	m.FS.skmap["preexisting-share"] = "preexisting-key"
	t.Cleanup(func() { _ = m.Close() })

	m.startEventPoller()
	select {
	case <-initialAPollerStarted:
	case <-time.After(time.Second):
		t.Fatal("session A's initial poller did not start")
	}
	aRefreshResult := make(chan error, 1)
	go func() { aRefreshResult <- m.getFileSystemContext(context.Background()) }()
	select {
	case <-aFilesystemStarted:
	case <-time.After(time.Second):
		t.Fatal("session A filesystem request did not pause at the test barrier")
	}

	loginParent, cancelLogin := context.WithCancel(context.Background())
	defer cancelLogin()
	loginCtx := &observedDoneContext{Context: loginParent, entered: make(chan struct{})}
	bLoginResult := make(chan error, 1)
	go func() { bLoginResult <- m.LoginWithKeysContext(loginCtx, "session-B", masterKeyB) }()
	select {
	case <-loginCtx.entered:
	case <-time.After(time.Second):
		t.Fatal("session B login did not begin waiting for session A's filesystem refresh")
	}
	if got := m.GetSessionID(); got != "session-A" {
		t.Fatalf("session changed while A's refresh was in flight: %q", got)
	}
	if !bytes.Equal(m.GetMasterKey(), masterKeyA) {
		t.Fatal("master key changed while session A's filesystem request was in flight")
	}
	select {
	case err := <-bLoginResult:
		t.Fatalf("session B login completed before session A's filesystem response was released: %v", err)
	default:
	}

	close(releaseAResponse)
	select {
	case err := <-aRefreshResult:
		if err != nil {
			t.Fatalf("session A getFileSystemContext() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session A filesystem refresh did not finish after its response was released")
	}
	select {
	case <-bFilesystemStarted:
	case <-time.After(time.Second):
		t.Fatal("session B post-auth filesystem request did not start")
	}
	select {
	case err := <-bLoginResult:
		if err != nil {
			t.Fatalf("LoginWithKeysContext(session B) error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session B login did not finish after both filesystem snapshots")
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close() after session replacement: %v", err)
	}

	if got := m.GetSessionID(); got != "session-B" {
		t.Fatalf("installed session ID = %q, want session B", got)
	}
	if !bytes.Equal(m.GetMasterKey(), masterKeyB) {
		t.Fatal("installed master key does not belong to session B")
	}
	if m.ssn != "sequence-B" {
		t.Fatalf("installed event sequence = %q, want session B sequence", m.ssn)
	}
	m.FS.mutex.Lock()
	cachedA := m.FS.lookup[nodeA.Hash]
	cachedB := m.FS.lookup[nodeB.Hash]
	m.FS.mutex.Unlock()
	if cachedA != nil {
		t.Fatalf("session A cache node = %#v, want prior-account cache to be cleared", cachedA)
	}
	if cachedB == nil || cachedB.name != "session B file" {
		t.Fatalf("session B cache node = %#v, want its correctly decrypted node", cachedB)
	}
	if got := m.FS.skmap["session-A-share"]; got != "" {
		t.Fatalf("session A share key survived account replacement: %q", got)
	}
	if got := m.FS.skmap["preexisting-share"]; got != "" {
		t.Fatalf("preexisting share key survived account replacement: %q", got)
	}
	if got := m.FS.skmap["session-B-share"]; got != "share-key-B" {
		t.Fatalf("session B share key = %q, want new account's key", got)
	}

	var sawBPoller bool
	for {
		select {
		case observation := <-pollerRequests:
			switch observation.sid {
			case "session-A":
				if observation.sn != "initial-A-sequence" && observation.sn != "sequence-A" {
					t.Errorf("session A poller used mixed sequence %q", observation.sn)
				}
			case "session-B":
				sawBPoller = true
				if observation.sn != "sequence-B" {
					t.Errorf("session B poller used mixed sequence %q", observation.sn)
				}
			default:
				t.Errorf("poller used unexpected session %q", observation.sid)
			}
		default:
			if !sawBPoller {
				t.Fatal("session B event poller was not observed")
			}
			return
		}
	}
}

func TestAPIRequestKeepsCredentialSnapshotWhileQueued(t *testing.T) {
	requestObserved := make(chan sessionRequestObservation, 1)
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		requestObserved <- sessionRequestObservation{
			path: req.URL.Path,
			sid:  req.URL.Query().Get("sid"),
			sn:   apiAction(body),
		}
		return apiTestResponse(http.StatusOK, `[{"mstrg":100,"cstrg":1}]`), nil
	}), 0)
	defer m.Close()
	m.sid = "session-A"
	m.k = bytes.Repeat([]byte{0x11}, aes.BlockSize)

	releaseGate, err := m.acquireAPIGate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctxParent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &observedDoneContext{Context: ctxParent, entered: make(chan struct{})}
	quotaResult := make(chan error, 1)
	go func() {
		_, err := m.GetQuotaContext(ctx)
		quotaResult <- err
	}()
	select {
	case <-ctx.entered:
	case <-time.After(time.Second):
		releaseGate()
		t.Fatal("quota request did not queue behind the held API gate")
	}

	keyB := bytes.Repeat([]byte{0x22}, aes.BlockSize)
	if err := m.installSessionContext(context.Background(), sessionCredentials{
		sessionID: "session-B",
		masterKey: keyB,
	}); err != nil {
		releaseGate()
		t.Fatalf("install session B: %v", err)
	}
	releaseGate()
	select {
	case err := <-quotaResult:
		if err == nil || !strings.Contains(err.Error(), "replaced session") {
			t.Fatalf("queued GetQuotaContext() error = %v, want stale-session rejection", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued quota request did not finish after the session changed")
	}
	select {
	case observation := <-requestObserved:
		t.Fatalf("stale queued API request was sent: %#v", observation)
	default:
	}
	if got := m.GetSessionID(); got != "session-B" {
		t.Fatalf("installed session = %q, want session B", got)
	}
}

func TestAPIRequestUsesCapturedSessionDuringReplacement(t *testing.T) {
	requestStarted := make(chan sessionRequestObservation, 1)
	releaseResponse := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseResponse) }) }
	defer release()
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		requestStarted <- sessionRequestObservation{path: req.URL.Path, sid: req.URL.Query().Get("sid"), sn: apiAction(body)}
		<-releaseResponse
		return apiTestResponse(http.StatusOK, `[{"mstrg":100,"cstrg":1}]`), nil
	}), 0)
	defer m.Close()
	m.sid = "session-A"
	m.k = bytes.Repeat([]byte{0x51}, aes.BlockSize)

	quotaResult := make(chan error, 1)
	go func() {
		_, err := m.GetQuotaContext(context.Background())
		quotaResult <- err
	}()
	select {
	case observation := <-requestStarted:
		if observation.path != "/cs" || observation.sn != "uq" || observation.sid != "session-A" {
			release()
			t.Fatalf("in-flight API request = %#v, want session A quota", observation)
		}
	case <-time.After(time.Second):
		t.Fatal("quota request did not reach transport")
	}

	installResult := make(chan error, 1)
	go func() {
		installResult <- m.installSessionContext(context.Background(), sessionCredentials{
			sessionID: "session-B",
			masterKey: bytes.Repeat([]byte{0x52}, aes.BlockSize),
		})
	}()
	select {
	case err := <-installResult:
		if err != nil {
			t.Fatalf("install session B error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session replacement did not finish while the API request remained in flight")
	}
	if got := m.GetSessionID(); got != "session-B" {
		t.Fatalf("installed session = %q, want session B", got)
	}
	release()
	select {
	case err := <-quotaResult:
		if err != nil {
			t.Fatalf("in-flight GetQuotaContext() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight quota request did not finish under its captured session")
	}
}

func TestUploadFinalizePinsSessionThroughLocalCommit(t *testing.T) {
	masterKeyA := bytes.Repeat([]byte{0x41}, aes.BlockSize)
	resultNode := finalizedUploadNodeForKey(t, masterKeyA, "finalized-session-A", "session A result")
	responseBody, err := json.Marshal([]UploadCompleteResp{{F: []FSNode{resultNode}}})
	if err != nil {
		t.Fatal(err)
	}
	finalizeStarted := make(chan struct{})
	releaseFinalize := make(chan struct{})
	observations := make(chan sessionRequestObservation, 2)
	var finalizeOnce sync.Once
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		action := apiAction(body)
		sid := req.URL.Query().Get("sid")
		observations <- sessionRequestObservation{path: req.URL.Path, sid: sid, sn: action}
		switch action {
		case "u":
			return apiTestResponse(http.StatusOK, `[{"p":"https://mega.invalid/upload-token"}]`), nil
		case "p":
			finalizeOnce.Do(func() { close(finalizeStarted) })
			<-releaseFinalize
			return apiTestResponse(http.StatusOK, string(responseBody)), nil
		default:
			return nil, fmt.Errorf("unexpected API action %q", action)
		}
	}), 0)
	defer m.Close()
	m.sid = "session-A"
	m.k = append([]byte(nil), masterKeyA...)
	parent := &Node{fs: m.FS, hash: "parent-A"}
	u, err := m.NewUploadContext(context.Background(), parent, "result", 0)
	if err != nil {
		t.Fatalf("NewUploadContext() error = %v", err)
	}
	u.completion_handle = []byte("completion-handle")
	u.chunk_macs[0] = make([]byte, aes.BlockSize)

	finishResult := make(chan error, 1)
	go func() {
		node, err := u.FinishContext(context.Background())
		if err == nil && (node == nil || node.hash != resultNode.Hash) {
			err = fmt.Errorf("FinishContext node = %v, want %q", node, resultNode.Hash)
		}
		finishResult <- err
	}()
	select {
	case <-finalizeStarted:
	case <-time.After(time.Second):
		t.Fatal("upload finalize request did not reach the test barrier")
	}

	installParent, cancelInstall := context.WithCancel(context.Background())
	defer cancelInstall()
	installCtx := &observedDoneContext{Context: installParent, entered: make(chan struct{})}
	installResult := make(chan error, 1)
	go func() {
		installResult <- m.installSessionContext(installCtx, sessionCredentials{
			sessionID: "session-B",
			masterKey: bytes.Repeat([]byte{0x42}, aes.BlockSize),
		})
	}()
	select {
	case <-installCtx.entered:
	case <-time.After(time.Second):
		close(releaseFinalize)
		t.Fatal("session B did not queue behind the in-flight upload finalize")
	}
	if got := m.GetSessionID(); got != "session-A" {
		close(releaseFinalize)
		t.Fatalf("session changed during session A finalize: %q", got)
	}
	close(releaseFinalize)
	select {
	case err := <-finishResult:
		if err != nil {
			t.Fatalf("FinishContext() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upload finalize did not commit after receiving its confirmed response")
	}
	select {
	case err := <-installResult:
		if err != nil {
			t.Fatalf("install session B error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session B did not install after session A finalize completed")
	}
	close(observations)
	for observation := range observations {
		if observation.path != "/cs" || observation.sid != "session-A" {
			t.Errorf("upload API request = %#v, want session A", observation)
		}
	}
}

func TestUploadOperationsRejectReplacedSession(t *testing.T) {
	var apiCalls int
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		apiCalls++
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		if action := apiAction(body); action != "u" {
			return nil, fmt.Errorf("unexpected API action %q", action)
		}
		if sid := req.URL.Query().Get("sid"); sid != "session-A" {
			return nil, fmt.Errorf("upload initialization used session %q, want session A", sid)
		}
		return apiTestResponse(http.StatusOK, `[{"p":"https://mega.invalid/upload-token"}]`), nil
	}), 0)
	defer m.Close()
	m.sid = "session-A"
	m.k = bytes.Repeat([]byte{0x31}, aes.BlockSize)
	parent := &Node{fs: m.FS, hash: "parent-A"}
	u, err := m.NewUploadContext(context.Background(), parent, "disposable", 0)
	if err != nil {
		t.Fatalf("NewUploadContext() error = %v", err)
	}
	if !u.sessionBound || u.session.sessionID != "session-A" {
		t.Fatalf("upload session binding = %#v (bound %v), want session A", u.session, u.sessionBound)
	}
	if err := m.installSessionContext(context.Background(), sessionCredentials{
		sessionID: "session-B",
		masterKey: bytes.Repeat([]byte{0x32}, aes.BlockSize),
	}); err != nil {
		t.Fatalf("install session B: %v", err)
	}
	if err := u.UploadChunkContext(context.Background(), 0, nil); err == nil || !strings.Contains(err.Error(), "replaced session") {
		t.Fatalf("UploadChunkContext() error = %v, want replaced-session error", err)
	}
	if _, err := u.FinishContext(context.Background()); err == nil || !strings.Contains(err.Error(), "replaced session") {
		t.Fatalf("FinishContext() error = %v, want replaced-session error", err)
	}
	if apiCalls != 1 {
		t.Fatalf("API calls after stale upload operations = %d, want only the original initialization", apiCalls)
	}
}

func TestDownloadOperationsRejectReplacedSession(t *testing.T) {
	fileKey := bytes.Repeat([]byte{0x41}, aes.BlockSize)
	encryptedAttr, err := encryptAttr(fileKey, FileAttr{Name: "disposable-download"})
	if err != nil {
		t.Fatalf("encrypt download attributes: %v", err)
	}
	var apiCalls, transferCalls int
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/cs":
			apiCalls++
			if sid := req.URL.Query().Get("sid"); sid != "session-A" {
				return nil, fmt.Errorf("download initialization used session %q, want session A", sid)
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			if action := apiAction(body); action != "g" {
				return nil, fmt.Errorf("unexpected API action %q", action)
			}
			return apiTestResponse(http.StatusOK, fmt.Sprintf(`[{"g":"https://mega.invalid/transfer","s":16,"at":%q}]`, encryptedAttr)), nil
		case "/transfer/0-15":
			transferCalls++
			return apiTestResponse(http.StatusOK, string(bytes.Repeat([]byte{0}, aes.BlockSize))), nil
		default:
			return nil, fmt.Errorf("unexpected request path %q", req.URL.Path)
		}
	}), 0)
	defer m.Close()
	m.sid = "session-A"
	m.k = bytes.Repeat([]byte{0x31}, aes.BlockSize)
	src := &Node{
		fs:                m.FS,
		sessionGeneration: m.FS.sessionGeneration,
		hash:              "download-A",
		meta: NodeMeta{
			key: fileKey,
			iv:  bytes.Repeat([]byte{0x51}, aes.BlockSize),
			mac: bytes.Repeat([]byte{0x61}, aes.BlockSize),
		},
	}
	d, err := m.NewDownloadContext(context.Background(), src)
	if err != nil {
		t.Fatalf("NewDownloadContext() error = %v", err)
	}
	if !d.sessionBound || d.session.sessionID != "session-A" {
		t.Fatalf("download session binding = %#v (bound %v), want session A", d.session, d.sessionBound)
	}
	if len(d.chunk_macs) != 1 || d.chunk_macs[0] != nil {
		t.Fatalf("initial chunk MAC state = %#v, want one unset chunk", d.chunk_macs)
	}
	if err := m.installSessionContext(context.Background(), sessionCredentials{
		sessionID: "session-B",
		masterKey: bytes.Repeat([]byte{0x32}, aes.BlockSize),
	}); err != nil {
		t.Fatalf("install session B: %v", err)
	}
	if _, err := d.DownloadChunkContext(context.Background(), 0); err == nil || !strings.Contains(err.Error(), "replaced session") {
		t.Fatalf("DownloadChunkContext() error = %v, want replaced-session error", err)
	}
	if err := d.FinishContext(context.Background()); err == nil || !strings.Contains(err.Error(), "replaced session") {
		t.Fatalf("FinishContext() error = %v, want replaced-session error", err)
	}
	if apiCalls != 1 {
		t.Fatalf("API calls after stale download operations = %d, want only the original initialization", apiCalls)
	}
	if transferCalls != 0 {
		t.Fatalf("transfer requests after stale download operations = %d, want zero", transferCalls)
	}
	if d.chunk_macs[0] != nil {
		t.Fatalf("stale download changed local chunk MAC state to %x", d.chunk_macs[0])
	}
}

func TestDownloadSnapshotsMetadataAcrossFilesystemRefresh(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x21}, aes.BlockSize)
	nodeA := finalizedUploadNodeForKey(t, masterKey, "download-refresh", "before-refresh")
	nodeB := finalizedUploadNodeWithComponentKey(t, masterKey, "download-refresh", "after-refresh", []uint32{11, 12, 13, 14, 15, 16, 17, 18})
	filesystemResponse, err := json.Marshal([]map[string]any{{
		"f":  []map[string]any{filesystemAPIWireNode(nodeB)},
		"sn": "refreshed-sequence",
	}})
	if err != nil {
		t.Fatal(err)
	}

	transferReader, transferWriter := io.Pipe()
	transferStarted := make(chan struct{})
	var transferOnce sync.Once
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/cs":
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			switch apiAction(body) {
			case "g":
				return apiTestResponse(http.StatusOK, fmt.Sprintf(`[{
					"g":"https://mega.invalid/transfer",
					"s":16,
					"at":%q
				}]`, nodeA.Attr)), nil
			case "f":
				return apiTestResponse(http.StatusOK, string(filesystemResponse)), nil
			default:
				return nil, fmt.Errorf("unexpected API action %q", apiAction(body))
			}
		case "/transfer/0-15":
			transferOnce.Do(func() { close(transferStarted) })
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       transferReader,
			}, nil
		case "/sc":
			<-req.Context().Done()
			return nil, req.Context().Err()
		default:
			return nil, fmt.Errorf("unexpected request path %q", req.URL.Path)
		}
	}), 0)
	t.Cleanup(func() {
		_ = transferWriter.Close()
		_ = transferReader.Close()
		_ = m.Close()
	})
	m.sid = "session-A"
	m.k = append([]byte(nil), masterKey...)

	m.FS.mutex.Lock()
	src, addErr := m.addFSNodeWithMasterKey(nodeA, masterKey)
	m.FS.mutex.Unlock()
	if addErr != nil {
		t.Fatalf("add initial download node: %v", addErr)
	}
	m.FS.mutex.Lock()
	sourceIV := append([]byte(nil), src.meta.iv...)
	sourceMAC := append([]byte(nil), src.meta.mac...)
	m.FS.mutex.Unlock()

	d, err := m.NewDownloadContext(context.Background(), src)
	if err != nil {
		t.Fatalf("NewDownloadContext() error = %v", err)
	}
	if !bytes.Equal(d.source_iv, sourceIV) || !bytes.Equal(d.source_mac, sourceMAC) {
		t.Fatalf("download metadata snapshot = iv %x/mac %x, want iv %x/mac %x", d.source_iv, d.source_mac, sourceIV, sourceMAC)
	}
	if d.session.sessionID != "session-A" || !d.sessionBound {
		t.Fatalf("download session binding = %#v (bound %v), want session A", d.session, d.sessionBound)
	}

	sourceMACWords, err := bytes_to_a32(d.source_mac)
	if err != nil {
		t.Fatal(err)
	}
	macData, err := a32_to_bytes([]uint32{sourceMACWords[0], 0, sourceMACWords[1], 0})
	if err != nil {
		t.Fatal(err)
	}
	chunkMAC := make([]byte, aes.BlockSize)
	cipher.NewCBCDecrypter(d.aes_block, zero_iv).CryptBlocks(chunkMAC, macData)
	plaintext := make([]byte, aes.BlockSize)
	cipher.NewCBCDecrypter(d.aes_block, d.iv).CryptBlocks(plaintext, chunkMAC)
	ciphertext := append([]byte(nil), plaintext...)
	cipher.NewCTR(d.aes_block, sourceIV).XORKeyStream(ciphertext, ciphertext)

	chunkResult := make(chan struct {
		chunk []byte
		err   error
	}, 1)
	go func() {
		chunk, err := d.DownloadChunkContext(context.Background(), 0)
		chunkResult <- struct {
			chunk []byte
			err   error
		}{chunk: chunk, err: err}
	}()
	select {
	case <-transferStarted:
	case <-time.After(time.Second):
		t.Fatal("download transfer did not start")
	}

	refreshResult := make(chan error, 1)
	go func() { refreshResult <- m.getFileSystemContext(context.Background()) }()
	select {
	case err := <-refreshResult:
		if err != nil {
			t.Fatalf("filesystem refresh error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("filesystem refresh did not finish while the download response was in flight")
	}

	m.FS.mutex.Lock()
	refreshed := m.FS.lookup[src.hash]
	refreshedName := refreshed.name
	refreshedIV := append([]byte(nil), refreshed.meta.iv...)
	refreshedMAC := append([]byte(nil), refreshed.meta.mac...)
	m.FS.mutex.Unlock()
	if refreshed != src || refreshedName != "after-refresh" {
		t.Fatalf("refreshed node = %p/%q, want original pointer %p with refreshed name", refreshed, refreshedName, src)
	}
	if bytes.Equal(refreshedIV, d.source_iv) || bytes.Equal(refreshedMAC, d.source_mac) {
		t.Fatalf("filesystem refresh did not replace download metadata: iv %x/mac %x", refreshedIV, refreshedMAC)
	}
	if got := m.GetSessionID(); got != "session-A" {
		t.Fatalf("session changed during filesystem refresh: %q", got)
	}

	if _, err := transferWriter.Write(ciphertext); err != nil {
		t.Fatalf("release transfer response: %v", err)
	}
	if err := transferWriter.Close(); err != nil {
		t.Fatalf("close transfer response: %v", err)
	}
	select {
	case result := <-chunkResult:
		if result.err != nil {
			t.Fatalf("DownloadChunkContext() error = %v", result.err)
		}
		if !bytes.Equal(result.chunk, plaintext) {
			t.Fatalf("downloaded chunk = %x, want %x from the original node metadata", result.chunk, plaintext)
		}
	case <-time.After(time.Second):
		t.Fatal("download chunk did not finish after the refresh response was released")
	}
	if err := d.FinishContext(context.Background()); err != nil {
		t.Fatalf("FinishContext() after metadata refresh = %v, want success using the original MAC", err)
	}
}

func TestNodeOperationsRejectPointersFromReplacedSession(t *testing.T) {
	var apiCalls int
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		apiCalls++
		return nil, errors.New("stale node reached the API transport")
	}), 0)
	defer m.Close()
	m.sid = "session-A"
	m.k = bytes.Repeat([]byte{0x61}, aes.BlockSize)
	oldNode := &Node{fs: m.FS, sessionGeneration: m.FS.sessionGeneration, hash: "old-node"}
	oldParent := &Node{fs: m.FS, sessionGeneration: m.FS.sessionGeneration, hash: "old-parent"}
	if err := m.installSessionContext(context.Background(), sessionCredentials{
		sessionID: "session-B",
		masterKey: bytes.Repeat([]byte{0x62}, aes.BlockSize),
	}); err != nil {
		t.Fatalf("install session B: %v", err)
	}

	operations := []struct {
		name string
		run  func() error
	}{
		{name: "node hash helper", run: func() error { _, err := oldNode.getHashContext(context.Background()); return err }},
		{name: "download", run: func() error { _, err := m.NewDownloadContext(context.Background(), oldNode); return err }},
		{name: "upload", run: func() error { _, err := m.NewUploadContext(context.Background(), oldParent, "stale", 0); return err }},
		{name: "rename", run: func() error { return m.RenameContext(context.Background(), oldNode, "renamed") }},
		{name: "move", run: func() error { return m.MoveContext(context.Background(), oldNode, oldParent) }},
		{name: "hard delete", run: func() error { return m.DeleteContext(context.Background(), oldNode, true) }},
		{name: "trash delete", run: func() error { return m.DeleteContext(context.Background(), oldNode, false) }},
		{name: "create directory", run: func() error { _, err := m.CreateDirContext(context.Background(), "stale", oldParent); return err }},
		{name: "link", run: func() error { _, err := m.LinkContext(context.Background(), oldNode, true); return err }},
		{name: "children lookup", run: func() error { _, err := m.FS.GetChildren(oldNode); return err }},
		{name: "path lookup", run: func() error { _, err := m.FS.PathLookup(oldNode, nil); return err }},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.run(); !errors.Is(err, errStaleNode) {
				t.Fatalf("operation error = %v, want stale-node rejection", err)
			}
		})
	}
	if apiCalls != 0 {
		t.Fatalf("stale node API requests = %d, want zero", apiCalls)
	}
}

func TestDeleteToTrashKeepsNodeAndTrashSessionAtomicWithReplacement(t *testing.T) {
	moveStarted := make(chan sessionRequestObservation, 1)
	releaseMove := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseMove) }) }
	defer release()
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		var moves []MoveFileMsg
		if err := json.Unmarshal(body, &moves); err != nil {
			return nil, err
		}
		if len(moves) != 1 || moves[0].Cmd != "m" {
			return nil, fmt.Errorf("move request = %#v", moves)
		}
		moveStarted <- sessionRequestObservation{path: req.URL.Path, sid: req.URL.Query().Get("sid"), sn: moves[0].T}
		<-releaseMove
		return apiTestResponse(http.StatusOK, `[0]`), nil
	}), 0)
	defer m.Close()
	m.sid = "session-A"
	m.k = bytes.Repeat([]byte{0x71}, aes.BlockSize)
	root := &Node{fs: m.FS, sessionGeneration: m.FS.sessionGeneration, hash: "root-A"}
	trash := &Node{fs: m.FS, sessionGeneration: m.FS.sessionGeneration, hash: "trash-A", ntype: TRASH}
	source := &Node{fs: m.FS, sessionGeneration: m.FS.sessionGeneration, hash: "source-A", parent: root}
	root.children = []*Node{source}
	m.FS.root = root
	m.FS.trash = trash
	m.FS.lookup[root.hash] = root
	m.FS.lookup[trash.hash] = trash
	m.FS.lookup[source.hash] = source

	deleteResult := make(chan error, 1)
	go func() { deleteResult <- m.DeleteContext(context.Background(), source, false) }()
	select {
	case observation := <-moveStarted:
		if observation.path != "/cs" || observation.sid != "session-A" || observation.sn != "trash-A" {
			release()
			t.Fatalf("trash move request = %#v, want session A and its trash handle", observation)
		}
	case <-time.After(time.Second):
		t.Fatal("delete-to-trash request did not reach its barrier")
	}

	installParent, cancelInstall := context.WithCancel(context.Background())
	defer cancelInstall()
	installCtx := &observedDoneContext{Context: installParent, entered: make(chan struct{})}
	installResult := make(chan error, 1)
	go func() {
		installResult <- m.installSessionContext(installCtx, sessionCredentials{
			sessionID: "session-B",
			masterKey: bytes.Repeat([]byte{0x72}, aes.BlockSize),
		})
	}()
	select {
	case <-installCtx.entered:
	case <-time.After(time.Second):
		release()
		t.Fatal("session replacement did not wait on the held filesystem lock")
	}
	if got := m.GetSessionID(); got != "session-A" {
		release()
		t.Fatalf("session changed before the atomic trash move completed: %q", got)
	}
	release()
	select {
	case err := <-deleteResult:
		if err != nil {
			t.Fatalf("DeleteContext(false) error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("trash move did not finish")
	}
	if source.parent != trash {
		t.Fatalf("source parent = %v, want the session A trash node", source.parent)
	}
	select {
	case err := <-installResult:
		if err != nil {
			t.Fatalf("install session B error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session replacement did not complete after trash move")
	}
	if got := m.GetSessionID(); got != "session-B" {
		t.Fatalf("installed session = %q, want session B", got)
	}
	if got := m.FS.GetTrash(); got != nil {
		t.Fatalf("new account trash pointer = %v, want cache cleared", got)
	}
}

func TestLinkContextCanCancelWhileWaitingForKeySnapshot(t *testing.T) {
	responseBodyClosed := make(chan struct{})
	var m *Mega
	calls := 0
	m = newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		m.FS.mutex.Lock()
		resp := apiTestResponse(http.StatusOK, `["public-handle"]`)
		resp.Body = &closeSignalReadCloser{Reader: bytes.NewBufferString(`["public-handle"]`), closed: responseBodyClosed}
		return resp, nil
	}), 1)
	n := &Node{fs: m.FS, hash: "node-handle", meta: NodeMeta{compkey: []byte("component-key")}}

	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &doneObservedAfterContext{Context: parent, after: responseBodyClosed, entered: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := m.LinkContext(ctx, n, true)
		result <- err
	}()
	select {
	case <-responseBodyClosed:
	case <-time.After(time.Second):
		m.FS.mutex.Unlock()
		t.Fatal("successful link response body was not consumed")
	}
	select {
	case <-ctx.entered:
	case <-time.After(time.Second):
		m.FS.mutex.Unlock()
		t.Fatal("LinkContext did not begin waiting for the key snapshot mutex")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("LinkContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		m.FS.mutex.Unlock()
		t.Fatal("LinkContext did not stop waiting after cancellation")
	}
	m.FS.mutex.Unlock()
	if calls != 1 {
		t.Fatalf("link API requests = %d, want 1", calls)
	}
}

func TestUploadFinishContextCommitsConfirmedFinalizeAfterCancellation(t *testing.T) {
	responseBodyClosed := make(chan struct{})
	masterKey, resultNode := finalizedUploadNode(t)
	resultBody, err := json.Marshal([]UploadCompleteResp{{F: []FSNode{resultNode}}})
	if err != nil {
		t.Fatal(err)
	}
	var m *Mega
	calls := 0
	m = newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		var request []UploadCompleteMsg
		if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
			return nil, err
		}
		if len(request) != 1 || request[0].Cmd != "p" {
			return nil, fmt.Errorf("request = %#v, want one finalize action", request)
		}
		resp := apiTestResponse(http.StatusOK, string(resultBody))
		resp.Body = &closeSignalReadCloser{Reader: bytes.NewReader(resultBody), closed: responseBodyClosed}
		return resp, nil
	}), 3)
	m.k = masterKey
	u := &Upload{
		m:                 m,
		parenthash:        "parent-handle",
		name:              "sample",
		kbytes:            make([]byte, aes.BlockSize),
		ukey:              []uint32{1, 2, 3, 4, 5, 6},
		completion_handle: []byte("completion-handle"),
	}

	m.FS.mutex.Lock()
	filesystemLocked := true
	defer func() {
		if filesystemLocked {
			m.FS.mutex.Unlock()
		}
	}()
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		node, err := u.FinishContext(parent)
		if err == nil && node == nil {
			err = errors.New("FinishContext returned a nil node after successful finalization")
		}
		if err == nil && node.hash != resultNode.Hash {
			err = fmt.Errorf("FinishContext returned node %q, want %q", node.hash, resultNode.Hash)
		}
		result <- err
	}()
	select {
	case <-responseBodyClosed:
	case <-time.After(time.Second):
		t.Fatal("successful finalize response body was not consumed")
	}
	cancel()
	blocked := waitForGoroutineBlockedAtMutex("FinishContext", time.Second)
	m.FS.mutex.Unlock()
	filesystemLocked = false
	if !blocked {
		t.Fatal("FinishContext did not wait for the filesystem mutex after consuming the successful finalize response")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("FinishContext() error = %v, want committed node after confirmed server success", err)
		}
	case <-time.After(time.Second):
		t.Fatal("FinishContext did not commit the confirmed server result after the filesystem mutex was released")
	}
	m.FS.mutex.Lock()
	if m.FS.lookup[resultNode.Hash] == nil {
		m.FS.mutex.Unlock()
		t.Fatalf("confirmed node %q is missing from the local filesystem cache", resultNode.Hash)
	}
	m.FS.mutex.Unlock()
	if calls != 1 {
		t.Fatalf("finalize API requests = %d, want exactly 1", calls)
	}
}

func TestUploadFinishContextRejectsMissingCompletionHandle(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected finalize request")
	}), 2)
	m.k = make([]byte, aes.BlockSize)
	u := &Upload{
		m:      m,
		name:   "missing handle",
		kbytes: make([]byte, aes.BlockSize),
		ukey:   make([]uint32, 6),
	}

	if _, err := u.FinishContext(context.Background()); err == nil || !strings.Contains(err.Error(), "completion handle is missing") {
		t.Fatalf("FinishContext() error = %v, want missing completion handle", err)
	}
	if calls != 0 {
		t.Fatalf("finalize API calls = %d, want 0", calls)
	}
	if u.finishState != uploadFinishIdle {
		t.Fatalf("finish state = %d, want idle after local validation failure", u.finishState)
	}
}

func TestUploadFinishContextDoesNotReplayAfterUncertainOutcome(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("connection lost after finalize request")
	}), 3)
	m.k = make([]byte, aes.BlockSize)
	u := &Upload{
		m:                 m,
		parenthash:        "parent",
		name:              "single use",
		kbytes:            make([]byte, aes.BlockSize),
		ukey:              make([]uint32, 6),
		completion_handle: []byte("completion-handle"),
	}

	if _, err := u.FinishContext(context.Background()); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("first FinishContext() error = %v, want uncertain outcome", err)
	}
	if _, err := u.FinishContext(context.Background()); err == nil || !strings.Contains(err.Error(), "already been attempted") {
		t.Fatalf("second FinishContext() error = %v, want replay rejection", err)
	}
	if calls != 1 {
		t.Fatalf("finalize API calls = %d, want exactly 1", calls)
	}
}

func finalizedUploadNode(t *testing.T) ([]byte, FSNode) {
	t.Helper()
	masterKey := make([]byte, aes.BlockSize)
	return masterKey, finalizedUploadNodeForKey(t, masterKey, "confirmed-new-handle", "sample")
}

func finalizedUploadNodeForKey(t *testing.T, masterKey []byte, hash, name string) FSNode {
	t.Helper()
	return finalizedUploadNodeWithComponentKey(t, masterKey, hash, name, []uint32{1, 2, 3, 4, 5, 6, 7, 8})
}

func finalizedUploadNodeWithComponentKey(t *testing.T, masterKey []byte, hash, name string, componentKey []uint32) FSNode {
	t.Helper()
	if len(componentKey) != 8 {
		t.Fatalf("component key length = %d, want 8", len(componentKey))
	}
	masterCipher, err := aes.NewCipher(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	componentBytes, err := a32_to_bytes(componentKey)
	if err != nil {
		t.Fatal(err)
	}
	encryptedComponentKey := make([]byte, len(componentBytes))
	if err := blockEncrypt(masterCipher, encryptedComponentKey, componentBytes); err != nil {
		t.Fatal(err)
	}
	fileKey := []uint32{
		componentKey[0] ^ componentKey[4],
		componentKey[1] ^ componentKey[5],
		componentKey[2] ^ componentKey[6],
		componentKey[3] ^ componentKey[7],
	}
	fileKeyBytes, err := a32_to_bytes(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	encryptedAttr, err := encryptAttr(fileKeyBytes, FileAttr{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return FSNode{
		Hash:   hash,
		Parent: "parent-handle",
		User:   "user-handle",
		T:      FILE,
		Attr:   encryptedAttr,
		Key:    "user-handle:" + base64urlencode(encryptedComponentKey),
		Ts:     1,
		Sz:     0,
	}
}

func filesystemAPIWireNode(node FSNode) map[string]any {
	wireNode := map[string]any{
		"h":  node.Hash,
		"p":  node.Parent,
		"u":  node.User,
		"t":  node.T,
		"a":  node.Attr,
		"k":  node.Key,
		"ts": node.Ts,
		"s":  node.Sz,
	}
	if node.SUser != "" {
		wireNode["su"] = node.SUser
		wireNode["sk"] = node.SKey
	}
	return wireNode
}

func finalizedUploadFolder(t *testing.T, masterKey []byte, hash, name, parent string) FSNode {
	t.Helper()
	componentKey := []uint32{1, 2, 3, 4}
	componentBytes, err := a32_to_bytes(componentKey)
	if err != nil {
		t.Fatal(err)
	}
	masterCipher, err := aes.NewCipher(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	encryptedComponentKey := make([]byte, len(componentBytes))
	if err := blockEncrypt(masterCipher, encryptedComponentKey, componentBytes); err != nil {
		t.Fatal(err)
	}
	encryptedAttr, err := encryptAttr(componentBytes, FileAttr{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return FSNode{
		Hash:   hash,
		Parent: parent,
		User:   "user-handle",
		T:      FOLDER,
		Attr:   encryptedAttr,
		Key:    "user-handle:" + base64urlencode(encryptedComponentKey),
		Ts:     1,
		SUser:  "shared-user",
		SKey:   "shared-key",
	}
}

func TestUploadChunkContextCancellationClosesSuccessfulResponseBody(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, aes.BlockSize))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := &closeTrackingReadCloser{Reader: bytes.NewReader(nil)}
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		cancel()
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       body,
		}, nil
	}), 1)
	u := &Upload{
		m:         m,
		name:      "sample",
		uploadUrl: "https://mega.invalid/upload",
		aes_block: block,
		iv:        make([]byte, aes.BlockSize),
		kiv:       make([]byte, aes.BlockSize),
		chunks:    []chunkSize{{position: 0, size: 1}},
	}

	err = u.UploadChunkContext(ctx, 0, []byte{1})
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, context.Canceled) {
		t.Fatalf("UploadChunkContext() error = %v, want unknown outcome and context.Canceled", err)
	}
	if !body.closed {
		t.Fatal("successful response body was not closed after cancellation")
	}
}

func TestPostAuthInitCancellationStopsAndJoinsSessionPoller(t *testing.T) {
	pollerStarted := make(chan struct{})
	pollerExited := make(chan struct{})
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/cs":
			return apiTestResponse(http.StatusOK, `[{"f":[{"h":"root","t":2}],"sn":"session-sequence"}]`), nil
		case "/sc":
			close(pollerStarted)
			<-req.Context().Done()
			close(pollerExited)
			return nil, req.Context().Err()
		default:
			return nil, fmt.Errorf("unexpected request path %q", req.URL.Path)
		}
	}), 1)
	m.k = make([]byte, aes.BlockSize)
	t.Cleanup(func() { _ = m.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- m.postAuthInitContext(ctx) }()
	select {
	case <-pollerStarted:
	case <-time.After(time.Second):
		t.Fatal("session poller did not start after filesystem listing succeeded")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("postAuthInitContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("postAuthInitContext() did not return after cancellation")
	}
	select {
	case <-pollerExited:
	default:
		t.Fatal("postAuthInitContext() returned before its session poller exited")
	}

	m.eventMu.Lock()
	eventDone, eventCancel := m.eventDone, m.eventCancel
	m.eventMu.Unlock()
	if eventDone != nil || eventCancel != nil {
		t.Fatal("session poller state was not cleared after failed initialization")
	}
}

func TestContextMutationsCanCancelWhileWaitingForFSMutex(t *testing.T) {
	tests := []struct {
		name string
		call func(*Mega, context.Context) error
	}{
		{
			name: "move",
			call: func(m *Mega, ctx context.Context) error {
				return m.MoveContext(ctx, &Node{hash: "source"}, &Node{hash: "parent"})
			},
		},
		{
			name: "rename",
			call: func(m *Mega, ctx context.Context) error {
				return m.RenameContext(ctx, &Node{hash: "source"}, "renamed")
			},
		},
		{
			name: "create directory",
			call: func(m *Mega, ctx context.Context) error {
				_, err := m.CreateDirContext(ctx, "directory", &Node{hash: "parent"})
				return err
			},
		},
		{
			name: "delete permanently",
			call: func(m *Mega, ctx context.Context) error {
				return m.DeleteContext(ctx, &Node{hash: "source"}, true)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("unexpected API request while filesystem mutex is held")
			}), 1)
			m.FS.mutex.Lock()

			parent, cancel := context.WithCancel(context.Background())
			ctx := &observedDoneContext{Context: parent, entered: make(chan struct{})}
			result := make(chan error, 1)
			go func() { result <- tt.call(m, ctx) }()
			select {
			case <-ctx.entered:
			case <-time.After(time.Second):
				cancel()
				m.FS.mutex.Unlock()
				t.Fatal("mutation did not begin waiting for the filesystem mutex")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("mutation error = %v, want context.Canceled", err)
				}
			case <-time.After(time.Second):
				m.FS.mutex.Unlock()
				t.Fatal("mutation did not stop waiting after cancellation")
			}
			if m.FS.mutex.TryLock() {
				m.FS.mutex.Unlock()
				t.Fatal("canceled mutation unexpectedly released the caller's filesystem mutex")
			}
			m.FS.mutex.Unlock()
		})
	}
}

func TestDownloadChunkContextCancellationStopsRetries(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, aes.BlockSize))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	}), 5)
	d := &Download{
		m:           m,
		src:         &Node{name: "sample", meta: NodeMeta{iv: make([]byte, aes.BlockSize)}},
		resourceUrl: "https://mega.invalid/download",
		aes_block:   block,
		iv:          make([]byte, aes.BlockSize),
		mac_enc:     cipher.NewCBCEncrypter(block, zero_iv),
		chunks:      []chunkSize{{position: 0, size: 1}},
		chunk_macs:  make([][]byte, 1),
	}

	result := make(chan error, 1)
	go func() {
		_, err := d.DownloadChunkContext(ctx, 0)
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DownloadChunkContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("download chunk did not stop after cancellation")
	}
	if calls != 1 {
		t.Fatalf("transport calls = %d, want 1", calls)
	}
}

func TestEventPollerUsesSessionLifetimeAndCloseStopsIt(t *testing.T) {
	started := make(chan struct{})
	cancelObserved := make(chan struct{})
	allowTransportReturn := make(chan struct{})
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		close(started)
		<-req.Context().Done()
		close(cancelObserved)
		<-allowTransportReturn
		return nil, req.Context().Err()
	}), 1)
	m.startEventPoller()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("event poller did not start")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- m.Close() }()
	select {
	case <-cancelObserved:
	case <-time.After(time.Second):
		t.Fatal("Close() did not cancel the session event request")
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Close() returned before the poller exited: %v", err)
	default:
	}
	close(allowTransportReturn)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close() did not return after the poller exited")
	}
}

func TestGetFileSystemContextJoinsOldPollerBeforeTakingFilesystemMutex(t *testing.T) {
	oldEventRequestStarted := make(chan struct{})
	releaseOldEventResponse := make(chan struct{})
	oldEventBodyClosed := make(chan struct{})
	filesystemBodyClosed := make(chan struct{})
	newPollerStarted := make(chan string, 1)
	var scMu sync.Mutex
	scCalls := 0
	var m *Mega
	m = newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/sc":
			scMu.Lock()
			scCalls++
			call := scCalls
			scMu.Unlock()
			if call == 1 {
				close(oldEventRequestStarted)
				<-releaseOldEventResponse
				body := []byte(`{"sn":"old-event-sequence","a":[{"a":"t","t":{"f":[]}}]}`)
				resp := apiTestResponse(http.StatusOK, string(body))
				resp.Body = &closeSignalReadCloser{Reader: bytes.NewReader(body), closed: oldEventBodyClosed}
				return resp, nil
			}
			select {
			case newPollerStarted <- req.URL.Query().Get("sn"):
			default:
			}
			<-req.Context().Done()
			return nil, req.Context().Err()
		case "/cs":
			body := []byte(`[{"f":[{"h":"root","t":2}],"sn":"fresh-session-sequence"}]`)
			resp := apiTestResponse(http.StatusOK, string(body))
			resp.Body = &closeSignalReadCloser{Reader: bytes.NewReader(body), closed: filesystemBodyClosed}
			return resp, nil
		default:
			return nil, fmt.Errorf("unexpected request path %q", req.URL.Path)
		}
	}), 1)
	m.k = make([]byte, aes.BlockSize)
	t.Cleanup(func() { _ = m.Close() })

	m.FS.mutex.Lock()
	filesystemLocked := true
	defer func() {
		if filesystemLocked {
			m.FS.mutex.Unlock()
		}
	}()
	m.startEventPoller()
	select {
	case <-oldEventRequestStarted:
	case <-time.After(time.Second):
		t.Fatal("old session poller did not issue its event request")
	}
	m.eventMu.Lock()
	oldPollerDone := m.eventDone
	m.eventMu.Unlock()
	if oldPollerDone == nil {
		t.Fatal("old session poller has no completion signal")
	}
	close(releaseOldEventResponse)
	select {
	case <-oldEventBodyClosed:
	case <-time.After(time.Second):
		t.Fatal("old session event response was not consumed")
	}
	if !waitForGoroutineBlockedAtMutex("processAddNode", time.Second) {
		t.Fatal("old poller did not pause at its filesystem-lock acquisition")
	}

	result := make(chan error, 1)
	go func() { result <- m.getFileSystemContext(context.Background()) }()
	select {
	case <-filesystemBodyClosed:
	case <-time.After(time.Second):
		t.Fatal("filesystem refresh did not fetch its response while the old event handler was paused")
	}
	if !waitForMutexHeldByAnother(&m.eventMu, time.Second) {
		t.Fatal("filesystem refresh did not begin stopping and joining the old poller")
	}
	select {
	case <-oldPollerDone:
		t.Fatal("old poller unexpectedly completed while its event handler was blocked on FS.mutex")
	default:
	}
	select {
	case err := <-result:
		t.Fatalf("filesystem refresh returned before the old poller could acquire FS.mutex: %v", err)
	default:
	}

	m.FS.mutex.Unlock()
	filesystemLocked = false
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("getFileSystemContext() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("filesystem refresh deadlocked joining the old poller")
	}
	select {
	case <-oldPollerDone:
	case <-time.After(time.Second):
		t.Fatal("old poller did not exit after its event handler acquired and released FS.mutex")
	}
	select {
	case sn := <-newPollerStarted:
		if sn != "fresh-session-sequence" {
			t.Fatalf("new poller session sequence = %q, want refreshed sequence", sn)
		}
	case <-time.After(time.Second):
		t.Fatal("new session poller did not start after filesystem refresh")
	}
}

func TestLegacyAPIUsesBackgroundContext(t *testing.T) {
	seen := false
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen = true
		if req.Context() == nil || req.Context().Err() != nil {
			t.Errorf("legacy API request context = %v, want live background context", req.Context())
		}
		return apiTestResponse(http.StatusOK, `[{"mstrg":100,"cstrg":1}]`), nil
	}), 0)
	var _ func(string, string) error = m.Login
	var _ func(string, string, string) error = m.MultiFactorLogin
	var _ func(string, []byte) error = m.LoginWithKeys
	var _ func() (UserResp, error) = m.GetUser
	var _ func() (QuotaResp, error) = m.GetQuota
	var _ func(*Node) (*Download, error) = m.NewDownload
	var _ func(int) ([]byte, error) = (&Download{}).DownloadChunk
	var _ func(*Node, string, int64) (*Upload, error) = m.NewUpload
	var _ func(int, []byte) error = (&Upload{}).UploadChunk
	var _ func() (*Node, error) = (&Upload{}).Finish
	var _ func(*Node, *Node) error = m.Move
	var _ func(*Node, string) error = m.Rename
	var _ func(string, *Node) (*Node, error) = m.CreateDir
	var _ func(*Node, bool) error = m.Delete
	var _ func(*Node, bool) (string, error) = m.Link
	var _ func(*Node, string, *chan int) error = m.DownloadFile
	var _ func(string, *Node, string, *chan int) (*Node, error) = m.UploadFile
	if _, err := m.GetQuota(); err != nil {
		t.Fatalf("legacy GetQuota() error = %v", err)
	}
	if !seen {
		t.Fatal("legacy GetQuota() did not send its request")
	}
}

func TestDownloadFinishContextCancellation(t *testing.T) {
	for _, chunkMACs := range [][][]byte{nil, {nil}} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		d := &Download{chunk_macs: chunkMACs}
		if err := d.FinishContext(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("FinishContext() error = %v, want context.Canceled", err)
		}
	}
}

func TestDownloadChunkRetryLogUsesLockedNameSnapshot(t *testing.T) {
	var retryLog string
	var m *Mega
	var src *Node
	m = newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		m.FS.mutex.Lock()
		src.name = "renamed during request"
		m.FS.mutex.Unlock()
		return apiTestResponse(http.StatusInternalServerError, "retry"), nil
	}), 0)
	m.debugf = func(format string, args ...any) {
		retryLog = fmt.Sprintf(format, args...)
	}
	src = &Node{fs: m.FS, hash: "source", name: "initial name"}
	d := &Download{
		m:           m,
		src:         src,
		resourceUrl: "https://mega.invalid/download",
		chunks:      []chunkSize{{position: 0, size: 1}},
	}

	if _, err := d.DownloadChunkContext(context.Background(), 0); err == nil {
		t.Fatal("DownloadChunkContext() error = nil, want failed response")
	}
	if !strings.Contains(retryLog, "initial name") || strings.Contains(retryLog, "renamed during request") {
		t.Fatalf("retry log = %q, want the locked initial name snapshot", retryLog)
	}
}

func TestDownloadFinishContextCancellationDoesNotPoisonRetry(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, aes.BlockSize))
	if err != nil {
		t.Fatal(err)
	}
	chunkMACs := [][]byte{make([]byte, aes.BlockSize), make([]byte, aes.BlockSize)}
	macData := make([]byte, aes.BlockSize)
	macEnc := cipher.NewCBCEncrypter(block, zero_iv)
	for _, chunkMAC := range chunkMACs {
		macEnc.CryptBlocks(macData, chunkMAC)
	}
	words, err := bytes_to_a32(macData)
	if err != nil {
		t.Fatal(err)
	}
	wantMAC, err := a32_to_bytes([]uint32{words[0] ^ words[1], words[2] ^ words[3]})
	if err != nil {
		t.Fatal(err)
	}
	d := &Download{
		aes_block:  block,
		mac_enc:    cipher.NewCBCEncrypter(block, zero_iv),
		chunk_macs: chunkMACs,
		source_mac: wantMAC,
	}
	ctx := &cancelAfterContextChecks{Context: context.Background(), checksUntilCancel: 2}
	if err := d.FinishContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("FinishContext() error = %v, want context.Canceled", err)
	}
	if err := d.Finish(); err != nil {
		t.Fatalf("Finish() after canceled verification = %v, want nil", err)
	}
}

func TestDownloadFinishLegacyWrapper(t *testing.T) {
	if err := (&Download{}).Finish(); err != nil {
		t.Fatalf("Finish() on an empty download = %v, want nil", err)
	}
}

func TestCollectWorkerErrorsPreservesUnknownOutcome(t *testing.T) {
	errch := make(chan error, 1)
	errch <- uncertainOutcomeError("upload chunk", context.Canceled)

	got := collectWorkerErrors(context.Canceled, errch)
	if !errors.Is(got, ErrOutcomeUnknown) || !errors.Is(got, context.Canceled) {
		t.Fatalf("collectWorkerErrors() = %v, want unknown outcome and context.Canceled", got)
	}
}

func TestUploadChunkContextCancellationDoesNotMutateCallerBuffer(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, aes.BlockSize))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		t.Fatal("transport called after cancellation before dispatch")
		return nil, nil
	}), 1)
	u := &Upload{
		m:         m,
		name:      "sample",
		uploadUrl: "https://mega.invalid/upload",
		aes_block: block,
		iv:        make([]byte, aes.BlockSize),
		kiv:       make([]byte, aes.BlockSize),
		chunks:    []chunkSize{{position: 0, size: aes.BlockSize}},
	}
	chunk := bytes.Repeat([]byte{0x2a}, aes.BlockSize)
	original := append([]byte(nil), chunk...)
	ctx := &cancelAfterContextChecks{Context: context.Background(), checksUntilCancel: 1}
	if err := u.UploadChunkContext(ctx, 0, chunk); !errors.Is(err, context.Canceled) {
		t.Fatalf("UploadChunkContext() error = %v, want context.Canceled", err)
	}
	if !bytes.Equal(chunk, original) {
		t.Fatalf("UploadChunkContext() mutated caller buffer: got %x, want %x", chunk, original)
	}
	if calls != 0 {
		t.Fatalf("transport calls = %d, want 0", calls)
	}
}

func TestUploadChunkContextPaddingDoesNotMutateAdjacentCallerBytes(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, aes.BlockSize))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		t.Fatal("transport called after cancellation before dispatch")
		return nil, nil
	}), 1)
	u := &Upload{
		m:         m,
		name:      "sample",
		uploadUrl: "https://mega.invalid/upload",
		aes_block: block,
		iv:        make([]byte, aes.BlockSize),
		kiv:       make([]byte, aes.BlockSize),
		chunks:    []chunkSize{{position: 0, size: 15}},
	}
	backing := bytes.Repeat([]byte{0x2a}, 32)
	chunk := backing[3:18] // 15 bytes, with spare capacity beyond the slice.
	originalBacking := append([]byte(nil), backing...)
	ctx := &cancelAfterContextChecks{Context: context.Background(), checksUntilCancel: 1}
	if err := u.UploadChunkContext(ctx, 0, chunk); !errors.Is(err, context.Canceled) {
		t.Fatalf("UploadChunkContext() error = %v, want context.Canceled", err)
	}
	if !bytes.Equal(backing, originalBacking) {
		t.Fatalf("UploadChunkContext() mutated caller backing array: got %x, want %x", backing, originalBacking)
	}
	if calls != 0 {
		t.Fatalf("transport calls = %d, want 0", calls)
	}
}

func TestWorkerSettingsRejectNonPositiveCounts(t *testing.T) {
	m := New()
	initialUploadWorkers := m.ul_workers
	initialDownloadWorkers := m.dl_workers
	for _, workers := range []int{0, -1} {
		if err := m.SetUploadWorkers(workers); !errors.Is(err, EWORKER_COUNT_INVALID) {
			t.Errorf("SetUploadWorkers(%d) error = %v, want EWORKER_COUNT_INVALID", workers, err)
		}
		if m.ul_workers != initialUploadWorkers {
			t.Errorf("SetUploadWorkers(%d) changed count to %d", workers, m.ul_workers)
		}
		if err := m.SetDownloadWorkers(workers); !errors.Is(err, EWORKER_COUNT_INVALID) {
			t.Errorf("SetDownloadWorkers(%d) error = %v, want EWORKER_COUNT_INVALID", workers, err)
		}
		if m.dl_workers != initialDownloadWorkers {
			t.Errorf("SetDownloadWorkers(%d) changed count to %d", workers, m.dl_workers)
		}
	}
}

func TestUploadFileContextRejectsNonPositiveWorkerCountBeforeIO(t *testing.T) {
	for _, workers := range []int{0, -1} {
		t.Run(fmt.Sprintf("workers_%d", workers), func(t *testing.T) {
			calls := 0
			m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				t.Fatal("API called with invalid worker count")
				return nil, nil
			}), 1)
			m.ul_workers = workers
			_, err := m.UploadFileContext(context.Background(), "does-not-exist", nil, "", nil)
			if !errors.Is(err, EWORKER_COUNT_INVALID) {
				t.Fatalf("UploadFileContext() error = %v, want EWORKER_COUNT_INVALID", err)
			}
			if calls != 0 {
				t.Fatalf("API calls = %d, want 0", calls)
			}
		})
	}
}

func TestDownloadToPathRejectsNonPositiveWorkerCountsBeforeCreatingTemp(t *testing.T) {
	for _, workers := range []int{0, -1} {
		t.Run(fmt.Sprintf("workers_%d", workers), func(t *testing.T) {
			m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("API called with invalid worker count")
				return nil, nil
			}), 1)
			m.dl_workers = workers
			d := &Download{m: m, chunks: []chunkSize{{position: 0, size: 1}}}
			destination := filepath.Join(t.TempDir(), "download.bin")
			if err := downloadToPathContext(context.Background(), d, destination, nil); !errors.Is(err, EWORKER_COUNT_INVALID) {
				t.Fatalf("downloadToPathContext() error = %v, want EWORKER_COUNT_INVALID", err)
			}
			entries, err := os.ReadDir(filepath.Dir(destination))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("temporary destination files = %d, want 0", len(entries))
			}
		})
	}
}

func TestDownloadToPathCancellationPreservesExistingDestination(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "existing.bin")
	original := []byte("preserve this file")
	if err := os.WriteFile(destination, original, 0600); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	}), 1)
	m.dl_workers = 1
	block, err := aes.NewCipher(make([]byte, aes.BlockSize))
	if err != nil {
		t.Fatal(err)
	}
	d := &Download{
		m:           m,
		src:         &Node{name: "sample", meta: NodeMeta{iv: make([]byte, aes.BlockSize)}},
		resourceUrl: "https://mega.invalid/download",
		aes_block:   block,
		iv:          make([]byte, aes.BlockSize),
		mac_enc:     cipher.NewCBCEncrypter(block, zero_iv),
		chunks:      []chunkSize{{position: 0, size: 1}},
		chunk_macs:  make([][]byte, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- downloadToPathContext(ctx, d, destination, nil) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("download request did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("download error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("download did not stop after cancellation")
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("destination changed after cancellation: got %q, want %q", got, original)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(destination) {
		t.Fatalf("staging files remain after cancellation: %v", entries)
	}
}

func TestDownloadToPathPublishesOnlyAfterMACVerification(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "existing.bin")
	original := []byte("valid prior destination")
	if err := os.WriteFile(destination, original, 0600); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(make([]byte, aes.BlockSize))
	if err != nil {
		t.Fatal(err)
	}
	d := &Download{
		aes_block:  block,
		chunk_macs: [][]byte{make([]byte, aes.BlockSize)},
		src:        &Node{meta: NodeMeta{mac: make([]byte, 8)}},
	}
	if err := downloadToPathContext(context.Background(), d, destination, nil); !errors.Is(err, EMACMISMATCH) {
		t.Fatalf("download error = %v, want EMACMISMATCH", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("destination changed after MAC failure: got %q, want %q", got, original)
	}
}

func TestDownloadToPathReplacesExistingFileOnSuccess(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "existing.bin")
	if err := os.WriteFile(destination, []byte("old contents"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := downloadToPathContext(context.Background(), &Download{}, destination, nil); err != nil {
		t.Fatalf("downloadToPathContext() = %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("published zero-byte download = %q, want empty", got)
	}
}

