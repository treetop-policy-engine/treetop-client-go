//go:build integration

package treetop

import (
	"context"
	"os"
	"testing"
)

func TestTreetopContainerCompatibility(t *testing.T) {
	baseURL := integrationEnv(t, "TREETOP_E2E_URL")
	accessValue := integrationEnv(t, "TREETOP_E2E_ACCESS_TOKEN")
	uploadValue := integrationEnv(t, "TREETOP_E2E_UPLOAD_TOKEN")

	access, err := NewAccessToken(accessValue)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(baseURL, WithAccessToken(access))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := client.Live(ctx); err != nil {
		t.Fatalf("live probe: %v", err)
	}
	ready, err := client.Ready(ctx)
	if err != nil || !ready {
		t.Fatalf("ready probe: ready=%t, err=%v", ready, err)
	}
	version, err := client.Version(ctx)
	if err != nil || version.Version != "v0.0.15" {
		t.Fatalf("version: %#v, err=%v", version, err)
	}
	status, err := client.Status(ctx)
	if err != nil || status.RequestLimits != DefaultRequestLimits() {
		t.Fatalf("status: %#v, err=%v", status, err)
	}

	upload, err := NewUploadToken(uploadValue)
	if err != nil {
		t.Fatal(err)
	}
	uploader, err := client.Uploader(upload)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := uploader.UploadPolicies(ctx, `
permit (
    principal in Group::"admins",
    action == Action::"view",
    resource == Document::"doc-42"
);`)
	if err != nil || metadata.Policies.Entries != 1 {
		t.Fatalf("upload policies: %#v, err=%v", metadata, err)
	}

	user, err := NewUser("alice", UserInGroups("admins", "operators"))
	if err != nil {
		t.Fatal(err)
	}
	action, err := NewAction("view")
	if err != nil {
		t.Fatal(err)
	}
	resource, err := NewResource("Document", "doc-42")
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewRequest(UserPrincipal(user), action, resource)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := client.IsAllowed(ctx, request)
	if err != nil || !allowed {
		t.Fatalf("authorize: allowed=%t, err=%v", allowed, err)
	}

	policies, err := client.UserPolicies(ctx, "alice", FilterGroups("admins", "operators"))
	if err != nil || len(policies.Policies) != 1 || len(policies.Matches) != 1 {
		t.Fatalf("user policies: %#v, err=%v", policies, err)
	}
}

func integrationEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Skipf("%s is not set", name)
	}
	return value
}
