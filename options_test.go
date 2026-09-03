package treetop

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithRootCAPEMPreservesCustomRootPool(t *testing.T) {
	first := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer first.Close()
	second := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer second.Close()

	roots := x509.NewCertPool()
	roots.AddCert(first.Certificate())
	secondPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: second.Certificate().Raw})
	custom := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	client, err := New(second.URL, WithHTTPClient(custom), WithRootCAPEM(secondPEM))
	if err != nil {
		t.Fatal(err)
	}
	transport := client.http.Transport.(*http.Transport)
	for i, certificate := range []*x509.Certificate{first.Certificate(), second.Certificate()} {
		if _, err := certificate.Verify(x509.VerifyOptions{Roots: transport.TLSClientConfig.RootCAs}); err != nil {
			t.Fatalf("custom root %d was not retained: %v", i, err)
		}
	}
	if roots == transport.TLSClientConfig.RootCAs {
		t.Fatal("custom root pool was mutated instead of cloned")
	}
}

func TestCustomTransportHTTP2PreferenceIsPreserved(t *testing.T) {
	original := &http.Transport{ForceAttemptHTTP2: false}
	client, err := New("https://example.com", WithHTTPClient(&http.Client{Transport: original}))
	if err != nil {
		t.Fatal(err)
	}
	transport := client.http.Transport.(*http.Transport)
	if transport.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 was enabled on a caller-supplied transport")
	}
	if transport == original {
		t.Fatal("caller-supplied transport was not cloned")
	}
}
