package appservice

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClient_UnixSocket(t *testing.T) {

	tmpDir := t.TempDir()
	socket := path.Join(tmpDir, "socket")

	l, err := net.Listen("unix", socket)
	assert.NoError(t, err)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `
{
  "device_id": "ABC1234",
  "user_id": "@joe:example.org"
}`)
	}))

	ts.Listener.Close()
	ts.Listener = l
	ts.Start()
	defer ts.Close()
	as := Create()
	as.Registration = &Registration{}
	err = as.SetHomeserverURL(fmt.Sprintf("unix://%s", socket))
	assert.NoError(t, err)
	client := as.Client("user1")
	resp, err := client.Whoami(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "@joe:example.org", string(resp.UserID))
}
