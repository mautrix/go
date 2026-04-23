package mautrix

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"go.mau.fi/util/exsync"
)

func newTestClient(t *testing.T, serverURL string) *Client {
	t.Helper()
	parsedURL, err := url.Parse(serverURL)
	require.NoError(t, err)
	return &Client{
		HomeserverURL:       parsedURL,
		Client:              http.DefaultClient,
		Log:                 zerolog.New(io.Discard),
		DefaultHTTPRetries:  1,
		DefaultHTTPBackoff:  200 * time.Millisecond,
		RequestRetryTrigger: exsync.NewEvent(),
	}
}

func TestRequestRetryTriggerRetriesActiveAttempt(t *testing.T) {
	requestStarted := make(chan struct{})
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch attempts.Add(1) {
		case 1:
			close(requestStarted)
			<-r.Context().Done()
		case 2:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			t.Fatalf("unexpected extra request attempt %d", attempts.Load())
		}
	}))
	t.Cleanup(server.Close)

	client := newTestClient(t, server.URL)
	var response struct {
		OK bool `json:"ok"`
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := client.MakeRequest(context.Background(), http.MethodGet, server.URL, nil, &response)
		errCh <- err
	}()

	select {
	case <-requestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for initial request attempt")
	}

	resetAt := time.Now()
	client.RequestRetryTrigger.Notify()

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for retried request to finish")
	}

	require.True(t, response.OK)
	require.EqualValues(t, 2, attempts.Load())
	require.Less(t, time.Since(resetAt), 150*time.Millisecond)
}

func TestRequestRetryTriggerUsesNormalRetryBudget(t *testing.T) {
	requestStarted := make(chan struct{})
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch attempts.Add(1) {
		case 1:
			close(requestStarted)
			<-r.Context().Done()
		default:
			t.Fatalf("unexpected extra request attempt %d", attempts.Load())
		}
	}))
	t.Cleanup(server.Close)

	client := newTestClient(t, server.URL)
	client.DefaultHTTPRetries = 0

	errCh := make(chan error, 1)
	go func() {
		_, err := client.MakeRequest(context.Background(), http.MethodGet, server.URL, nil, nil)
		errCh <- err
	}()

	select {
	case <-requestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for request start")
	}

	client.RequestRetryTrigger.Notify()

	select {
	case err := <-errCh:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for canceled request to finish")
	}

	require.EqualValues(t, 1, attempts.Load())
}

func TestCallerCancellationDoesNotRetry(t *testing.T) {
	requestStarted := make(chan struct{})
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		close(requestStarted)
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)

	client := newTestClient(t, server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := client.MakeRequest(ctx, http.MethodGet, server.URL, nil, nil)
		errCh <- err
	}()

	select {
	case <-requestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for request start")
	}

	cancel()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for canceled request to finish")
	}

	require.EqualValues(t, 1, attempts.Load())
}

func TestRequestRetryTriggerDoesNotInterruptBackoff(t *testing.T) {
	firstAttemptDone := make(chan time.Time, 1)
	secondAttemptStarted := make(chan time.Time, 1)
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch attempts.Add(1) {
		case 1:
			w.WriteHeader(http.StatusBadGateway)
			firstAttemptDone <- time.Now()
		case 2:
			secondAttemptStarted <- time.Now()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected extra request attempt %d", attempts.Load())
		}
	}))
	t.Cleanup(server.Close)

	client := newTestClient(t, server.URL)
	client.DefaultHTTPBackoff = 250 * time.Millisecond
	errCh := make(chan error, 1)
	go func() {
		_, err := client.MakeRequest(context.Background(), http.MethodGet, server.URL, nil, nil)
		errCh <- err
	}()

	var firstAt time.Time
	select {
	case firstAt = <-firstAttemptDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for first attempt to fail")
	}

	time.Sleep(50 * time.Millisecond)
	client.RequestRetryTrigger.Notify()

	var secondAt time.Time
	select {
	case secondAt = <-secondAttemptStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for retried request")
	}

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for request completion")
	}

	require.GreaterOrEqual(t, secondAt.Sub(firstAt), 200*time.Millisecond)
	require.EqualValues(t, 2, attempts.Load())
}

func TestRequestRetryTriggerCancelsStreamingBody(t *testing.T) {
	streamStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		close(streamStarted)
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)

	client := newTestClient(t, server.URL)
	_, resp, err := client.MakeFullRequestWithResp(context.Background(), FullRequest{
		Method:           http.MethodGet,
		URL:              server.URL,
		DontReadResponse: true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	defer resp.Body.Close()

	select {
	case <-streamStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for stream start")
	}

	buf := make([]byte, 5)
	n, err := io.ReadFull(resp.Body, buf)
	require.NoError(t, err)
	require.Equal(t, 5, n)
	require.Equal(t, "hello", string(buf))

	client.RequestRetryTrigger.Notify()

	_, err = resp.Body.Read(make([]byte, 1))
	require.Error(t, err)
}

func TestDontReadResponseCleanupRunsOnBodyClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	t.Cleanup(server.Close)

	client := newTestClient(t, server.URL)
	attemptCtxCh := make(chan context.Context, 1)
	client.RequestHook = func(req *http.Request) {
		select {
		case attemptCtxCh <- req.Context():
		default:
		}
	}

	_, resp, err := client.MakeFullRequestWithResp(context.Background(), FullRequest{
		Method:           http.MethodGet,
		URL:              server.URL,
		DontReadResponse: true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	var attemptCtx context.Context
	select {
	case attemptCtx = <-attemptCtxCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for attempt context")
	}

	select {
	case <-attemptCtx.Done():
		t.Fatal("attempt context canceled before body close")
	case <-time.After(100 * time.Millisecond):
	}

	require.NoError(t, resp.Body.Close())

	select {
	case <-attemptCtx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for attempt context cleanup after body close")
	}
	require.ErrorIs(t, context.Cause(attemptCtx), context.Canceled)
}

func TestRedirectErrorCleansUpAttemptContext(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, server.URL+"/final", http.StatusFound)
	}))
	t.Cleanup(server.Close)

	client := newTestClient(t, server.URL)
	httpClient := server.Client()
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return errors.New("stop redirect")
	}
	client.Client = httpClient

	attemptCtxCh := make(chan context.Context, 1)
	client.RequestHook = func(req *http.Request) {
		select {
		case attemptCtxCh <- req.Context():
		default:
		}
	}

	_, _, err := client.MakeFullRequestWithResp(context.Background(), FullRequest{
		Method: http.MethodGet,
		URL:    server.URL,
	})
	require.Error(t, err)

	var attemptCtx context.Context
	select {
	case attemptCtx = <-attemptCtxCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for attempt context")
	}

	select {
	case <-attemptCtx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for attempt context cleanup after redirect error")
	}
	require.ErrorIs(t, context.Cause(attemptCtx), context.Canceled)
}

type readSeekCloser struct {
	*bytes.Reader
}

func (r readSeekCloser) Close() error {
	return nil
}

type testRoundTripper func(*http.Request) (*http.Response, error)

func (trt testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return trt(req)
}

type writerToReadCloser struct {
	*bytes.Reader
}

func (wrc *writerToReadCloser) Close() error {
	return nil
}

func (wrc *writerToReadCloser) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, wrc.Reader)
}

func TestRequestRetryTriggerReplaysRequestBody(t *testing.T) {
	requestStarted := make(chan struct{})
	bodyBytes := []byte("hello retry body")
	var attempts atomic.Int32
	receivedBodies := make(chan []byte, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		receivedBodies <- body

		switch attempts.Add(1) {
		case 1:
			close(requestStarted)
			<-r.Context().Done()
		case 2:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			t.Fatalf("unexpected extra request attempt %d", attempts.Load())
		}
	}))
	t.Cleanup(server.Close)

	client := newTestClient(t, server.URL)
	var response struct {
		OK bool `json:"ok"`
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := client.MakeFullRequest(context.Background(), FullRequest{
			Method:        http.MethodPost,
			URL:           server.URL,
			RequestBody:   readSeekCloser{bytes.NewReader(bodyBytes)},
			RequestLength: int64(len(bodyBytes)),
			ResponseJSON:  &response,
		})
		errCh <- err
	}()

	select {
	case <-requestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for initial request attempt")
	}

	client.RequestRetryTrigger.Notify()

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for retried request to finish")
	}

	require.True(t, response.OK)
	require.EqualValues(t, 2, attempts.Load())
	require.Equal(t, bodyBytes, <-receivedBodies)
	require.Equal(t, bodyBytes, <-receivedBodies)
}

func TestDontReadResponseCleanupWrapperPreservesWriterTo(t *testing.T) {
	body := &writerToReadCloser{Reader: bytes.NewReader([]byte("hello writer-to"))}
	client := newTestClient(t, "https://example.com")
	client.Client = &http.Client{
		Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/octet-stream"}},
				Body:       body,
			}, nil
		}),
	}

	_, resp, err := client.MakeFullRequestWithResp(context.Background(), FullRequest{
		Method:           http.MethodGet,
		URL:              "https://example.com",
		DontReadResponse: true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	writerTo, ok := resp.Body.(io.WriterTo)
	require.True(t, ok)

	var copied bytes.Buffer
	_, err = writerTo.WriteTo(&copied)
	require.NoError(t, err)
	require.Equal(t, "hello writer-to", copied.String())
	require.NoError(t, resp.Body.Close())
}

func TestDontReadResponseWithoutRetryTriggerDoesNotWrapBody(t *testing.T) {
	body := &writerToReadCloser{Reader: bytes.NewReader([]byte("hello raw body"))}
	client := newTestClient(t, "https://example.com")
	client.RequestRetryTrigger = nil
	client.Client = &http.Client{
		Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/octet-stream"}},
				Body:       body,
			}, nil
		}),
	}

	_, resp, err := client.MakeFullRequestWithResp(context.Background(), FullRequest{
		Method:           http.MethodGet,
		URL:              "https://example.com",
		DontReadResponse: true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Same(t, body, resp.Body)
	require.NoError(t, resp.Body.Close())
}
