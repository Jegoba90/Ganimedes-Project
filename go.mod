// go.mod declares this folder as a Go "module": a versioned collection of
// packages built and released together. The module path below is also the
// import prefix for every package in the repo, and it matches the GitHub URL
// so `go install github.com/Jegoba90/Ganimedes-Project/cmd/ganimedes@latest`
// works once the repo is public.
module github.com/Jegoba90/Ganimedes-Project

// Require the patched standard library as well as the language version. The
// gateway depends on net/http, html/template and crypto/x509; an old toolchain
// remains a security dependency even when there are no third-party modules.
go 1.26.10
