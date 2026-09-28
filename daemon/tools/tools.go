// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build tools

// Build-time tools of the release, pinned as a module of their own so that Dependabot moves
// their versions and go.sum vouches for them. Nothing here is linked into wardend or wardenctl:
// this module is not part of ./... of the daemon, govulncheck does not scan it and the SBOM does
// not list it. The release workflow and the maintainer install the tools with
// `go -C tools install tool` (scripts/release.sh reads the version from go.mod here).
package tools

import _ "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod"
