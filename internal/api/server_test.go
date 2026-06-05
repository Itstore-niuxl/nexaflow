package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"nexaflow/internal/config"
)

func TestAuthTokenCarriesRole(t *testing.T) {
	server := New(nil, config.Config{AuthPassword: "admin-pass", AuthSecret: "test-secret"})

	token, err := server.signAuthToken("alice", authRoleViewer, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	identity, ok := server.verifyAuthToken(token)
	if !ok {
		t.Fatal("expected token to verify")
	}
	if identity.Actor != "alice" {
		t.Fatalf("expected actor alice, got %q", identity.Actor)
	}
	if identity.Role != authRoleViewer {
		t.Fatalf("expected viewer role, got %q", identity.Role)
	}
}

func TestAuthTokenKeepsLegacyAdminRole(t *testing.T) {
	server := New(nil, config.Config{AuthPassword: "admin-pass", AuthSecret: "test-secret"})

	payload := "legacy|" + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	token := encoded + "." + server.authSignature(encoded)

	identity, ok := server.verifyAuthToken(token)
	if !ok {
		t.Fatal("expected legacy token to verify")
	}
	if identity.Actor != "legacy" {
		t.Fatalf("expected legacy actor, got %q", identity.Actor)
	}
	if identity.Role != authRoleAdmin {
		t.Fatalf("expected legacy admin role, got %q", identity.Role)
	}
}

func TestLoginRole(t *testing.T) {
	server := New(nil, config.Config{AuthPassword: "admin-pass", AuthReadOnlyPassword: "viewer-pass"})
	if role := server.loginRole("admin-pass"); role != authRoleAdmin {
		t.Fatalf("expected admin role, got %q", role)
	}
	if role := server.loginRole("viewer-pass"); role != authRoleViewer {
		t.Fatalf("expected viewer role, got %q", role)
	}
	if role := server.loginRole("bad-pass"); role != "" {
		t.Fatalf("expected empty role for invalid password, got %q", role)
	}
}

func TestRequestNeedsWriteAccess(t *testing.T) {
	getReq, _ := http.NewRequest(http.MethodGet, "/api/v1/collectors/config", nil)
	if requestNeedsWriteAccess(getReq) {
		t.Fatal("GET should not require write access")
	}

	postReq, _ := http.NewRequest(http.MethodPost, "/api/v1/collectors/config", nil)
	if !requestNeedsWriteAccess(postReq) {
		t.Fatal("POST should require write access")
	}

	healthReq, _ := http.NewRequest(http.MethodPost, "/healthz", nil)
	if requestNeedsWriteAccess(healthReq) {
		t.Fatal("non-api path should not require write access")
	}
}

func TestAuthRequiredBlocksViewerWrites(t *testing.T) {
	server := New(nil, config.Config{AuthPassword: "admin-pass", AuthReadOnlyPassword: "viewer-pass", AuthSecret: "test-secret"})
	viewerToken, err := server.signAuthToken("bob", authRoleViewer, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatalf("sign viewer token: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	handler := server.authRequired(next)

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/summary", nil)
	getReq.AddCookie(&http.Cookie{Name: authCookieName, Value: viewerToken})
	getResp := httptest.NewRecorder()
	handler.ServeHTTP(getResp, getReq)
	if getResp.Code != http.StatusAccepted {
		t.Fatalf("expected viewer GET to pass, got %d", getResp.Code)
	}

	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/collectors/config", nil)
	postReq.AddCookie(&http.Cookie{Name: authCookieName, Value: viewerToken})
	postResp := httptest.NewRecorder()
	handler.ServeHTTP(postResp, postReq)
	if postResp.Code != http.StatusForbidden {
		t.Fatalf("expected viewer POST to be forbidden, got %d", postResp.Code)
	}
}
