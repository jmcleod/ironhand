package api

import (
	"net/http"
	"strconv"
)

const (
	defaultPageLimit = 100
	maxPageLimit     = 200
)

// PaginationMeta is embedded in paginated list responses.
type PaginationMeta struct {
	TotalCount int  `json:"total_count"`
	Limit      int  `json:"limit"`
	Offset     int  `json:"offset"`
	HasMore    bool `json:"has_more"`
}

// parsePagination reads "limit" and "offset" query parameters from the
// request. Missing or invalid values fall back to defaults (offset=0,
// limit=defaultPageLimit). Negative values are clamped to 0; limit is
// capped at maxPageLimit.
func parsePagination(r *http.Request) (limit, offset int) {
	q := r.URL.Query()

	limit = defaultPageLimit
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxPageLimit {
		limit = maxPageLimit
	}

	offset = 0
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}

	return limit, offset
}

// paginateSlice returns (start, end) indices for slicing a collection of
// totalCount items, plus the filled PaginationMeta. If offset exceeds
// totalCount, start == end (empty page).
func paginateSlice(totalCount, limit, offset int) (start, end int, meta PaginationMeta) {
	start = offset
	if start > totalCount {
		start = totalCount
	}
	end = start + limit
	if end > totalCount {
		end = totalCount
	}
	meta = PaginationMeta{
		TotalCount: totalCount,
		Limit:      limit,
		Offset:     offset,
		HasMore:    end < totalCount,
	}
	return start, end, meta
}
