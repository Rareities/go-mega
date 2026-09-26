package mega

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type apiRoundTripFunc func(*http.Request) (*http.Response, error)

func (f apiRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type temporaryAPIError struct{ err error }

func (e temporaryAPIError) Error() string { return e.err.Error() }
func (e temporaryAPIError) Unwrap() error { return e.err }
func (temporaryAPIError) Timeout() bool   { return false }
func (temporaryAPIError) Temporary() bool { return true }

func newAPITestMega(transport http.RoundTripper, retries int) *Mega {
	return &Mega{
		config: config{
			baseurl: "https://mega.invalid",
			retries: retries,
		},
		client: &http.Client{Transport: transport},
		debugf: discardLogf,
		FS:     newMegaFS(),
	}
}

func apiTestResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestAPIRequestMutationAcceptedThenLostIsNotRetried(t *testing.T) {
	transportErr := errors.New("connection lost after request was sent")
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, transportErr
	}), 3)

	buf, err := m.api_request([]byte(`[{"a":"d","n":"node"}]`))
	if buf != nil {
		t.Fatalf("api_request() body = %q, want nil", buf)
	}
	if err == nil {
		t.Fatal("api_request() error = nil, want uncertain outcome")
	}
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("api_request() error = %v, want ErrOutcomeUnknown", err)
	}
	if !errors.Is(err, transportErr) {
		t.Errorf("api_request() error = %v, want wrapped transport error", err)
	}
	var uncertainErr *UncertainOutcomeError
	if !errors.As(err, &uncertainErr) {
		t.Errorf("api_request() error type = %T, want *UncertainOutcomeError", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestAPIRequestMalformedMutationResponseIsUncertain(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return apiTestResponse(http.StatusOK, "[malformed response"), nil
	}), 3)

	_, err := m.api_request([]byte(`[{"a":"m","n":"node"}]`))
	if err == nil {
		t.Fatal("api_request() error = nil, want uncertain outcome")
	}
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("api_request() error = %v, want ErrOutcomeUnknown", err)
	}
	if !errors.Is(err, EBADRESP) {
		t.Errorf("api_request() error = %v, want wrapped EBADRESP", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestAPIRequestNullMutationResponseIsUncertain(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return apiTestResponse(http.StatusOK, "[null]"), nil
	}), 3)

	_, err := m.api_request([]byte(`[{"a":"d","n":"node"}]`))
	if err == nil {
		t.Fatal("api_request() error = nil, want unknown outcome")
	}
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, EBADRESP) {
		t.Errorf("api_request() error = %v, want ErrOutcomeUnknown and EBADRESP", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestAPIRequestRequiresKnownMutationSuccessShape(t *testing.T) {
	tests := []struct {
		name    string
		request string
		body    string
		wantErr bool
	}{
		{name: "move numeric success", request: `[{"a":"m"}]`, body: "[0]"},
		{name: "rename numeric success", request: `[{"a":"a"}]`, body: "[0]"},
		{name: "delete numeric success", request: `[{"a":"d"}]`, body: "[0]"},
		{name: "delete empty per-node result success", request: `[{"a":"d"}]`, body: `[{"r":[]}]`},
		{name: "delete per-node numeric success", request: `[{"a":"d"}]`, body: `[{"r":[0]}]`},
		{name: "upload target success", request: `[{"a":"u","s":12}]`, body: `[{"p":"https://upload.invalid/ul/token"}]`},
		{name: "login success", request: `[{"a":"us"}]`, body: `[{"csid":"csid","privk":"private-key","k":"encrypted-key"}]`},
		{name: "link success", request: `[{"a":"l","n":"node"}]`, body: `["public-handle"]`},
		{name: "put nodes success", request: `[{"a":"p","n":[{"t":1}]}]`, body: `[{"f":[{"h":"handle","p":"parent","u":"owner","a":"encrypted-attributes","k":"owner:encoded-key","t":1}]}]`},
		{name: "put nodes missing owner is malformed", request: `[{"a":"p","n":[{"t":1}]}]`, body: `[{"f":[{"h":"handle","p":"parent","a":"encrypted-attributes","k":"owner:encoded-key","t":1}]}]`, wantErr: true},
		{name: "put nodes empty owner is malformed", request: `[{"a":"p","n":[{"t":1}]}]`, body: `[{"f":[{"h":"handle","p":"parent","u":"","a":"encrypted-attributes","k":"owner:encoded-key","t":1}]}]`, wantErr: true},
		{name: "move object is malformed", request: `[{"a":"m"}]`, body: `[{"unexpected":true}]`, wantErr: true},
		{name: "move err object is not success", request: `[{"a":"m"}]`, body: `[{"err":0}]`, wantErr: true},
		{name: "upload boolean is malformed", request: `[{"a":"u","s":12}]`, body: `[true]`, wantErr: true},
		{name: "upload missing target is malformed", request: `[{"a":"u","s":12}]`, body: `[{}]`, wantErr: true},
		{name: "upload relative target is malformed", request: `[{"a":"u","s":12}]`, body: `[{"p":"/ul/token"}]`, wantErr: true},
		{name: "login response is malformed", request: `[{"a":"us"}]`, body: `[{}]`, wantErr: true},
		{name: "link response is malformed", request: `[{"a":"l","n":"node"}]`, body: `[{}]`, wantErr: true},
		{name: "empty link is malformed", request: `[{"a":"l","n":"node"}]`, body: `[""]`, wantErr: true},
		{name: "move long numeric array is not established success", request: `[{"a":"m"}]`, body: `[0,0,0]`, wantErr: true},
		{name: "put nodes allows extra returned nodes", request: `[{"a":"p","n":[{"t":1}]}]`, body: `[{"f":[{"h":"handle","p":"parent","u":"owner","a":"encrypted-attributes","k":"owner:encoded-key","t":1},{"h":"other","p":"parent","u":"owner","a":"other-attributes","k":"owner:other-key","t":0}]}]`},
		{name: "put nodes rejects non-node extra result", request: `[{"a":"p","n":[{"t":1}]}]`, body: `[{"f":[{"h":"handle","p":"parent","u":"owner","a":"encrypted-attributes","k":"owner:encoded-key","t":1},true]}]`, wantErr: true},
		{name: "put nodes FILE response cannot be FOLDER", request: `[{"a":"p","n":[{"t":0}]}]`, body: `[{"f":[{"h":"handle","p":"parent","u":"owner","a":"encrypted-attributes","k":"owner:encoded-key","t":1}]}]`, wantErr: true},
		{name: "put nodes FOLDER response cannot be FILE", request: `[{"a":"p","n":[{"t":1}]}]`, body: `[{"f":[{"h":"handle","p":"parent","u":"owner","a":"encrypted-attributes","k":"owner:encoded-key","t":0}]}]`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return apiTestResponse(http.StatusOK, tt.body), nil
			}), 2)

			_, err := m.api_request([]byte(tt.request))
			if tt.wantErr {
				if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, EBADRESP) {
					t.Errorf("api_request() error = %v, want uncertain malformed-response error", err)
				}
			} else if err != nil {
				t.Errorf("api_request() error = %v, want nil", err)
			}
			if calls != 1 {
				t.Errorf("transport calls = %d, want 1", calls)
			}
		})
	}
}

func TestAPIRequestRejectsNegativeZeroErrorCodes(t *testing.T) {
	tests := []struct {
		name     string
		action   string
		response string
	}{
		{name: "top-level code", action: "m", response: "-0"},
		{name: "array code", action: "m", response: "[-0]"},
		{name: "embedded err field", action: "m", response: `[{"err":-0}]`},
		{name: "embedded delete result", action: "d", response: `[{"r":[-0]}]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return apiTestResponse(http.StatusOK, tt.response), nil
			}), 3)

			request := fmt.Sprintf(`[{"a":%q,"n":"node"}]`, tt.action)
			_, err := m.api_request([]byte(request))
			if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, EBADRESP) {
				t.Errorf("api_request() error = %v, want ErrOutcomeUnknown and EBADRESP", err)
			}
			if calls != 1 {
				t.Errorf("transport calls = %d, want 1", calls)
			}
		})
	}
}

func TestNewUploadMalformedTargetIsUncertain(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return apiTestResponse(http.StatusOK, `[{}]`), nil
	}), 3)
	parent := &Node{fs: m.FS, hash: "parent"}

	upload, err := m.NewUpload(parent, "file", 1)
	if upload != nil {
		t.Errorf("NewUpload() upload = %#v, want nil", upload)
	}
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, EBADRESP) {
		t.Errorf("NewUpload() error = %v, want ErrOutcomeUnknown and EBADRESP", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestGetLinkMalformedResponseIsUncertain(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return apiTestResponse(http.StatusOK, `[{}]`), nil
	}), 3)
	node := &Node{fs: m.FS, hash: "node"}

	link, err := m.getLink(node)
	if link != "" {
		t.Errorf("getLink() link = %q, want empty", link)
	}
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, EBADRESP) {
		t.Errorf("getLink() error = %v, want ErrOutcomeUnknown and EBADRESP", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestAPIRequestMalformedPutNodesResponseIsUncertain(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return apiTestResponse(http.StatusOK, `[{"f":[]}]`), nil
	}), 2)

	_, err := m.api_request([]byte(`[{"a":"p","n":[{"t":1}]}]`))
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, EBADRESP) {
		t.Errorf("api_request() error = %v, want uncertain malformed-response error", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestUploadFinishRejectsFolderResponseForFileRequest(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return apiTestResponse(http.StatusOK, `[{"f":[{"h":"handle","p":"parent","u":"owner","a":"encrypted-attributes","k":"owner:encoded-key","t":1}]}]`), nil
	}), 3)
	m.k = make([]byte, 16)

	upload := &Upload{
		m:                 m,
		parenthash:        "parent",
		name:              "file",
		kbytes:            make([]byte, 16),
		ukey:              make([]uint32, 6),
		completion_handle: []byte("upload-handle"),
	}

	node, err := upload.Finish()
	if node != nil {
		t.Errorf("Upload.Finish() node = %#v, want nil", node)
	}
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, EBADRESP) {
		t.Errorf("Upload.Finish() error = %v, want ErrOutcomeUnknown and EBADRESP", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestCreateDirMissingNodeOwnerIsUncertain(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return apiTestResponse(http.StatusOK, `[{"f":[{"h":"handle","p":"parent","a":"encrypted-attributes","k":"owner:encoded-key","t":1}]}]`), nil
	}), 2)
	m.k = make([]byte, 16)
	parent := &Node{fs: m.FS, hash: "parent"}

	node, err := m.CreateDir("folder", parent)
	if node != nil {
		t.Errorf("CreateDir() node = %#v, want nil", node)
	}
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, EBADRESP) {
		t.Errorf("CreateDir() error = %v, want ErrOutcomeUnknown and EBADRESP", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestCreateDirRejectsFileResponseForFolderRequest(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return apiTestResponse(http.StatusOK, `[{"f":[{"h":"handle","p":"parent","u":"owner","a":"encrypted-attributes","k":"owner:encoded-key","t":0}]}]`), nil
	}), 3)
	m.k = make([]byte, 16)
	parent := &Node{fs: m.FS, hash: "parent"}

	node, err := m.CreateDir("folder", parent)
	if node != nil {
		t.Errorf("CreateDir() node = %#v, want nil", node)
	}
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, EBADRESP) {
		t.Errorf("CreateDir() error = %v, want ErrOutcomeUnknown and EBADRESP", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestAPIRequestNon200PreservesStatusAndDoesNotSucceed(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return apiTestResponse(http.StatusServiceUnavailable, "temporarily unavailable"), nil
	}), 3)

	buf, err := m.api_request([]byte(`[{"a":"d","n":"node"}]`))
	if buf != nil {
		t.Errorf("api_request() body = %q, want nil", buf)
	}
	if err == nil {
		t.Fatal("api_request() error = nil, want HTTP status error")
	}
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("api_request() error = %v, want ErrOutcomeUnknown", err)
	}
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("api_request() error type = %T, want wrapped *HTTPStatusError", err)
	}
	if statusErr.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("HTTP status code = %d, want %d", statusErr.StatusCode, http.StatusServiceUnavailable)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestAPIRequestRetriesSafeRead(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return nil, temporaryAPIError{errors.New("temporary connection failure")}
		}
		return apiTestResponse(http.StatusOK, `[{"mstrg":123,"cstrg":0}]`), nil
	}), 1)

	buf, err := m.api_request([]byte(`[{"a":"uq","xfer":1}]`))
	if err != nil {
		t.Fatalf("api_request() error = %v, want nil", err)
	}
	if string(buf) != `[{"mstrg":123,"cstrg":0}]` {
		t.Errorf("api_request() body = %s, want quota response", buf)
	}
	if calls != 2 {
		t.Errorf("transport calls = %d, want 2", calls)
	}
}

func TestAPIRequestRejectsLongArrayAsSafeReadSuccess(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return apiTestResponse(http.StatusOK, `[0,0,0]`), nil
	}), 0)

	_, err := m.api_request([]byte(`[{"a":"uq","xfer":1}]`))
	if !errors.Is(err, EBADRESP) {
		t.Errorf("api_request() error = %v, want EBADRESP", err)
	}
	if errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("api_request() error = %v, safe-read malformed response is not an uncertain mutation", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestAPIRequestUnknownActionIsNotRetried(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("connection failure")
	}), 3)

	_, err := m.api_request([]byte(`[{"a":"future-action"}]`))
	if err == nil {
		t.Fatal("api_request() error = nil, want uncertain outcome")
	}
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("api_request() error = %v, want ErrOutcomeUnknown", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestAPIRequestUnknownActionMalformedResponseIsUncertain(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return apiTestResponse(http.StatusOK, `[true]`), nil
	}), 3)

	_, err := m.api_request([]byte(`[{"a":"future-action"}]`))
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, EBADRESP) {
		t.Errorf("api_request() error = %v, want ErrOutcomeUnknown and EBADRESP", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestAPIRequestPaymentRequiredWithoutChallengeIsUncertain(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return apiTestResponse(http.StatusPaymentRequired, ""), nil
	}), 3)

	_, err := m.api_request([]byte(`[{"a":"m","n":"node"}]`))
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusPaymentRequired {
		t.Errorf("api_request() error = %v, want preserved 402 status", err)
	}
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("api_request() error = %v, want ErrOutcomeUnknown", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestAPIRequestSecondPaymentRequiredIsUncertain(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 2 && req.Header.Get("X-Hashcash") != "1:AA:solved" {
			t.Errorf("continuation X-Hashcash = %q, want %q", req.Header.Get("X-Hashcash"), "1:AA:solved")
		}
		resp := apiTestResponse(http.StatusPaymentRequired, "")
		if calls == 1 {
			resp.Header.Set("X-Hashcash", "1:255::AA")
		}
		return resp, nil
	}), 3)

	_, err := m.apiRequestWithHashCash([]byte(`[{"a":"m","n":"node"}]`), func(token string, easiness int, _ time.Duration, _ int) (string, error) {
		if token != "AA" || easiness != 255 {
			t.Errorf("hashcash challenge = (%q, %d), want (%q, %d)", token, easiness, "AA", 255)
		}
		return "solved", nil
	})
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("api_request() error = %v, want ErrOutcomeUnknown", err)
	}
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusPaymentRequired {
		t.Errorf("api_request() error = %v, want preserved second 402 status", err)
	}
	if calls != 2 {
		t.Errorf("transport calls = %d, want 2 for the hashcash continuation", calls)
	}
}

func TestAPIRequestHashcashSolverFailureIsUncertain(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		resp := apiTestResponse(http.StatusPaymentRequired, "")
		resp.Header.Set("X-Hashcash", "1:1::AA")
		return resp, nil
	}), 3)
	solveErr := errors.New("hashcash solver failed")

	_, err := m.apiRequestWithHashCash([]byte(`[{"a":"m","n":"node"}]`), func(string, int, time.Duration, int) (string, error) {
		return "", solveErr
	})
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, solveErr) {
		t.Errorf("api_request() error = %v, want ErrOutcomeUnknown and solver cause", err)
	}
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusPaymentRequired {
		t.Errorf("api_request() error = %v, want preserved 402 status", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestAPIRequestMutationRedirectIsNotReplayed(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		resp := apiTestResponse(http.StatusTemporaryRedirect, "")
		resp.Header.Set("Location", "https://mega.invalid/redirect")
		return resp, nil
	}), 3)

	_, err := m.api_request([]byte(`[{"a":"m","n":"node"}]`))
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("api_request() error = %v, want ErrOutcomeUnknown", err)
	}
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("api_request() error = %v, want preserved 307 status", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestMoveAmbiguousFailureLeavesFilesystemUnchanged(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("connection lost after request was sent")
	}), 3)

	oldParent := &Node{fs: m.FS, hash: "old-parent"}
	newParent := &Node{fs: m.FS, hash: "new-parent"}
	src := &Node{fs: m.FS, hash: "node", parent: oldParent}
	oldParent.children = []*Node{src}
	m.FS.lookup[oldParent.hash] = oldParent
	m.FS.lookup[newParent.hash] = newParent
	m.FS.lookup[src.hash] = src

	err := m.Move(src, newParent)
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("Move() error = %v, want ErrOutcomeUnknown", err)
	}
	if src.parent != oldParent {
		t.Errorf("src.parent = %p, want old parent %p", src.parent, oldParent)
	}
	if len(oldParent.children) != 1 || oldParent.children[0] != src {
		t.Errorf("old parent children = %v, want the source node", oldParent.children)
	}
	if len(newParent.children) != 0 {
		t.Errorf("new parent children = %v, want empty", newParent.children)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestHardDeleteAmbiguousFailureLeavesFilesystemUnchanged(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("connection lost after request was sent")
	}), 3)

	parent := &Node{fs: m.FS, hash: "parent"}
	node := &Node{fs: m.FS, hash: "node", parent: parent}
	parent.children = []*Node{node}
	m.FS.lookup[parent.hash] = parent
	m.FS.lookup[node.hash] = node

	err := m.Delete(node, true)
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("Delete() error = %v, want ErrOutcomeUnknown", err)
	}
	if node.parent != parent {
		t.Errorf("node.parent = %p, want parent %p", node.parent, parent)
	}
	if len(parent.children) != 1 || parent.children[0] != node {
		t.Errorf("parent children = %v, want the node", parent.children)
	}
	if m.FS.lookup[node.hash] != node {
		t.Error("deleted node is no longer in the lookup table")
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestAPIRequestPreservesAPIErrorWithoutRetryingMutation(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return apiTestResponse(http.StatusOK, "[-3]"), nil
	}), 3)

	_, err := m.api_request([]byte(`[{"a":"d","n":"node"}]`))
	if !errors.Is(err, EAGAIN) {
		t.Errorf("api_request() error = %v, want EAGAIN", err)
	}
	if err != EAGAIN {
		t.Errorf("api_request() error = %v, want to preserve the EAGAIN sentinel identity", err)
	}
	if errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("api_request() error = %v, should preserve explicit API error", err)
	}
	if calls != 1 {
		t.Errorf("transport calls = %d, want 1", calls)
	}
}

func TestAPIRequestRedactsSessionIDFromErrorsAndLogs(t *testing.T) {
	const sid = "sid-secret-123"
	transportErr := errors.New("dial failed with token " + sid)
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, transportErr
	}), 2)
	m.sid = sid

	_, err := m.api_request([]byte(`[{"a":"d","n":"node"}]`))
	if err == nil {
		t.Fatal("api_request() error = nil, want transport failure")
	}
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, transportErr) {
		t.Errorf("api_request() error = %v, want outcome sentinel and original cause", err)
	}
	var requestErr *url.Error
	if !errors.As(err, &requestErr) {
		t.Fatalf("api_request() error type = %T, want wrapped *url.Error", err)
	}
	if strings.Contains(requestErr.URL, sid) || strings.Contains(requestErr.Error(), sid) {
		t.Errorf("extracted request error exposed session ID: URL=%q error=%q", requestErr.URL, requestErr)
	}
	for _, formatted := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		if strings.Contains(formatted, sid) {
			t.Errorf("formatted error exposed session ID: %q", formatted)
		}
	}
	if !strings.Contains(err.Error(), "dial failed") || !strings.Contains(err.Error(), "sid=[REDACTED]") {
		t.Errorf("sanitized error lost useful diagnostics: %q", err)
	}

	var logs strings.Builder
	calls := 0
	m = newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return nil, temporaryAPIError{errors.New("temporary connection failure")}
		}
		return apiTestResponse(http.StatusOK, `[{"mstrg":1,"cstrg":0}]`), nil
	}), 1)
	m.sid = sid
	m.debugf = func(format string, args ...any) { _, _ = fmt.Fprintf(&logs, format+"\n", args...) }
	if _, err := m.api_request([]byte(`[{"a":"uq","xfer":1}]`)); err != nil {
		t.Fatalf("read retry api_request() error = %v", err)
	}
	if strings.Contains(logs.String(), sid) {
		t.Errorf("retry log exposed session ID: %q", logs.String())
	}
	if !strings.Contains(logs.String(), "temporary connection failure") || !strings.Contains(logs.String(), "sid=[REDACTED]") {
		t.Errorf("retry log omitted useful sanitized diagnostics: %q", logs.String())
	}
}

func TestAPIRequestReadRetryClassification(t *testing.T) {
	t.Run("cancellation is not retried", func(t *testing.T) {
		calls := 0
		m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, context.Canceled
		}), 3)
		_, err := m.api_request([]byte(`[{"a":"uq","xfer":1}]`))
		if !errors.Is(err, context.Canceled) || calls != 1 {
			t.Errorf("api_request() error=%v calls=%d, want cancellation after one call", err, calls)
		}
	})

	t.Run("plain permanent transport error is not retried", func(t *testing.T) {
		calls := 0
		m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("permanent transport failure")
		}), 3)
		_, err := m.api_request([]byte(`[{"a":"uq","xfer":1}]`))
		if err == nil || calls != 1 {
			t.Errorf("api_request() error=%v calls=%d, want one permanent failure", err, calls)
		}
	})

	t.Run("TLS certificate error is not retried", func(t *testing.T) {
		calls := 0
		tlsErr := x509.UnknownAuthorityError{Cert: &x509.Certificate{}}
		m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, tlsErr
		}), 3)
		_, err := m.api_request([]byte(`[{"a":"uq","xfer":1}]`))
		var certErr x509.UnknownAuthorityError
		if !errors.As(err, &certErr) || calls != 1 {
			t.Errorf("api_request() error=%v calls=%d, want TLS error after one call", err, calls)
		}
	})

	t.Run("permanent client error status is not retried", func(t *testing.T) {
		calls := 0
		m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return apiTestResponse(http.StatusBadRequest, "bad request"), nil
		}), 3)
		_, err := m.api_request([]byte(`[{"a":"uq","xfer":1}]`))
		var statusErr *HTTPStatusError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusBadRequest || calls != 1 {
			t.Errorf("api_request() error=%v calls=%d, want HTTP 400 after one call", err, calls)
		}
	})

	t.Run("selected server error is retried", func(t *testing.T) {
		calls := 0
		m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return apiTestResponse(http.StatusServiceUnavailable, "busy"), nil
			}
			return apiTestResponse(http.StatusOK, `[{"mstrg":1,"cstrg":0}]`), nil
		}), 1)
		if _, err := m.api_request([]byte(`[{"a":"uq","xfer":1}]`)); err != nil || calls != 2 {
			t.Errorf("api_request() error=%v calls=%d, want successful retry", err, calls)
		}
	})
}

func TestAPIRequest429RetryAfterIsBounded(t *testing.T) {
	t.Run("zero delay retries", func(t *testing.T) {
		calls := 0
		m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				resp := apiTestResponse(http.StatusTooManyRequests, "rate limited")
				resp.Header.Set("Retry-After", "0")
				return resp, nil
			}
			return apiTestResponse(http.StatusOK, `[{"mstrg":1,"cstrg":0}]`), nil
		}), 1)
		if _, err := m.api_request([]byte(`[{"a":"uq","xfer":1}]`)); err != nil || calls != 2 {
			t.Errorf("api_request() error=%v calls=%d, want bounded retry", err, calls)
		}
	})

	t.Run("server delay above bound is not retried early", func(t *testing.T) {
		calls := 0
		m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			resp := apiTestResponse(http.StatusTooManyRequests, "rate limited")
			resp.Header.Set("Retry-After", "999999")
			return resp, nil
		}), 3)
		_, err := m.api_request([]byte(`[{"a":"uq","xfer":1}]`))
		var statusErr *HTTPStatusError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusTooManyRequests || calls != 1 {
			t.Errorf("api_request() error=%v calls=%d, want HTTP 429 without early retry", err, calls)
		}
	})
}

func TestAPIRequest503RetryAfterAboveBoundIsNotRetriedEarly(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		resp := apiTestResponse(http.StatusServiceUnavailable, "busy")
		resp.Header.Set("Retry-After", strings.Repeat("9", 40))
		return resp, nil
	}), 3)
	_, err := m.api_request([]byte(`[{"a":"uq","xfer":1}]`))
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusServiceUnavailable || calls != 1 {
		t.Errorf("api_request() error=%v calls=%d, want HTTP 503 without early retry", err, calls)
	}
}

func TestParseBoundedRetryAfter(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		value       string
		wantDelay   time.Duration
		wantPresent bool
		wantBounded bool
	}{
		{value: "2", wantDelay: 2 * time.Second, wantPresent: true, wantBounded: true},
		{value: "999999", wantPresent: true},
		{value: strings.Repeat("9", 40), wantPresent: true},
		{value: "invalid", wantBounded: true},
		{value: now.Add(3 * time.Second).Format(http.TimeFormat), wantDelay: 3 * time.Second, wantPresent: true, wantBounded: true},
	}
	for _, tt := range tests {
		delay, present, bounded := parseBoundedRetryAfter(tt.value, now)
		if delay != tt.wantDelay || present != tt.wantPresent || bounded != tt.wantBounded {
			t.Errorf("parseBoundedRetryAfter(%q) = (%v,%v,%v), want (%v,%v,%v)", tt.value, delay, present, bounded, tt.wantDelay, tt.wantPresent, tt.wantBounded)
		}
	}
}

func TestAPIFilesystemAllowsUnparentedSharedRootOnly(t *testing.T) {
	sharedRoot := json.RawMessage(`{"h":"shared","t":1,"u":"owner","a":"encrypted","k":"owner:key","ts":1,"su":"owner","sk":"share-key"}`)
	if err := apiFilesystemNodeError(sharedRoot); err != nil {
		t.Fatalf("shared root without a parent should be accepted: %v", err)
	}
	ordinaryFolder := json.RawMessage(`{"h":"folder","t":1,"u":"owner","a":"encrypted","k":"owner:key","ts":1}`)
	if err := apiFilesystemNodeError(ordinaryFolder); !errors.Is(err, EBADRESP) {
		t.Fatalf("ordinary folder without parent error=%v, want EBADRESP", err)
	}
}

func TestAPIRequestRetryExhaustionReturnsLastError(t *testing.T) {
	causes := []error{
		errors.New("temporary failure one"),
		errors.New("temporary failure two"),
		errors.New("temporary failure three"),
	}
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		cause := causes[calls]
		calls++
		return nil, temporaryAPIError{cause}
	}), 2)
	_, err := m.api_request([]byte(`[{"a":"uq","xfer":1}]`))
	if err == nil || calls != 3 {
		t.Fatalf("api_request() error=%v calls=%d, want final error after three attempts", err, calls)
	}
	if !errors.Is(err, causes[2]) || errors.Is(err, causes[0]) || !strings.Contains(err.Error(), causes[2].Error()) {
		t.Errorf("exhausted error = %v, want final attempt's original error", err)
	}
}

func TestAPIRequestRequiresActionSpecificReadFields(t *testing.T) {
	tests := []struct {
		name    string
		request string
		body    string
	}{
		{name: "prelogin version", request: `[{"a":"us0"}]`, body: `[{}]`},
		{name: "version two salt", request: `[{"a":"us0"}]`, body: `[{"v":2}]`},
		{name: "user handle", request: `[{"a":"ug"}]`, body: `[{}]`},
		{name: "quota used storage", request: `[{"a":"uq","xfer":1}]`, body: `[{"mstrg":100}]`},
		{name: "filesystem node fields", request: `[{"a":"f","c":1}]`, body: `[{"f":[{"h":"node","t":0}],"sn":"1"}]`},
		{name: "download fields", request: `[{"a":"g","g":1,"n":"node"}]`, body: `[{"g":"https://download.invalid/file","s":0}]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return apiTestResponse(http.StatusOK, tt.body), nil
			}), 3)
			_, err := m.api_request([]byte(tt.request))
			if !errors.Is(err, EBADRESP) || calls != 1 {
				t.Errorf("api_request() error=%v calls=%d, want EBADRESP without retry", err, calls)
			}
		})
	}
}

func TestGetFileSystemRejectsMalformedNodeWithoutPartialListing(t *testing.T) {
	calls := 0
	m := newAPITestMega(apiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return apiTestResponse(http.StatusOK, `[{"f":[{"h":"root","t":2},{"h":"broken","t":0}],"sn":"1"}]`), nil
	}), 2)
	if err := m.getFileSystem(); !errors.Is(err, EBADRESP) {
		t.Errorf("getFileSystem() error=%v, want EBADRESP", err)
	}
	if len(m.FS.lookup) != 0 {
		t.Errorf("getFileSystem() left %d partial nodes in the listing", len(m.FS.lookup))
	}
	if calls != 1 {
		t.Errorf("API calls=%d, want 1", calls)
	}
}
