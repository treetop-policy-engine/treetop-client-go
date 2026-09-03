package treetop

const testPoliciesMetadataJSON = `{
	"allow_upload":true,
	"schema_validation_mode":"permissive",
	"policies":{"timestamp":"` + testLoadedAt + `","sha256":"abc","size":9,"entries":1,"content":"permit();"},
	"labels":{"timestamp":"` + testLoadedAt + `","sha256":"","size":0,"entries":0,"content":""},
	"schema":{"timestamp":"` + testLoadedAt + `","sha256":"","size":0,"entries":0,"content":""}
}`
