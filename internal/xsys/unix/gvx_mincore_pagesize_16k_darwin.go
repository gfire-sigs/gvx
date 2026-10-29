//go:build darwin && arm64 && pagesize_16k && !pagesize_64k

package unix

// MincorePageSize is the page size that the Linux mincore(2) contract of this
// overlay uses: one result byte per page and a page-aligned start address.
// It equals hostarch.PageSize of the same build, because the Sentry sizes the
// result vector with that constant. Pagesize_16k builds use 16KB pages.
const MincorePageSize = 16384
