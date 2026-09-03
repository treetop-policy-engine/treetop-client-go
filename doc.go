// Package treetop provides a safe, context-aware HTTP client for Treetop REST
// policy authorization servers.
//
// A Client is safe for concurrent use and should be reused so its underlying
// HTTP connection pool can be reused. Upload operations are exposed through a
// separate Uploader value, which can only be created with a validated upload
// token.
package treetop
