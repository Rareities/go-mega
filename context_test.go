package mega

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type observedDoneContext struct {
	context.Context
	once    sync.Once
	entered chan struct{}
}

type cancelAfterContextChecks struct {
	context.Context
	checksUntilCancel int
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
		src:        &Node{meta: NodeMeta{mac: wantMAC}},
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
