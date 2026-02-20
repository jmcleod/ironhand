package api

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePagination(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantLimit  int
		wantOffset int
	}{
		{"defaults", "", defaultPageLimit, 0},
		{"custom limit", "limit=50", 50, 0},
		{"custom offset", "offset=10", defaultPageLimit, 10},
		{"both", "limit=25&offset=5", 25, 5},
		{"limit exceeds max", "limit=500", maxPageLimit, 0},
		{"limit at max", "limit=200", maxPageLimit, 0},
		{"negative limit uses default", "limit=-1", defaultPageLimit, 0},
		{"negative offset uses zero", "offset=-5", defaultPageLimit, 0},
		{"non-numeric limit", "limit=abc", defaultPageLimit, 0},
		{"non-numeric offset", "offset=xyz", defaultPageLimit, 0},
		{"zero limit uses default", "limit=0", defaultPageLimit, 0},
		{"zero offset", "offset=0", defaultPageLimit, 0},
		{"limit one", "limit=1", 1, 0},
		{"large offset", "offset=999999", defaultPageLimit, 999999},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/test"
			if tt.query != "" {
				url += "?" + tt.query
			}
			r := httptest.NewRequest("GET", url, nil)
			limit, offset := parsePagination(r)
			assert.Equal(t, tt.wantLimit, limit, "limit")
			assert.Equal(t, tt.wantOffset, offset, "offset")
		})
	}
}

func TestPaginateSlice(t *testing.T) {
	tests := []struct {
		name       string
		total      int
		limit      int
		offset     int
		wantStart  int
		wantEnd    int
		wantCount  int
		wantMore   bool
		wantLimit  int
		wantOffset int
	}{
		{
			name: "first page", total: 50, limit: 10, offset: 0,
			wantStart: 0, wantEnd: 10, wantCount: 50, wantMore: true,
			wantLimit: 10, wantOffset: 0,
		},
		{
			name: "second page", total: 50, limit: 10, offset: 10,
			wantStart: 10, wantEnd: 20, wantCount: 50, wantMore: true,
			wantLimit: 10, wantOffset: 10,
		},
		{
			name: "last page partial", total: 25, limit: 10, offset: 20,
			wantStart: 20, wantEnd: 25, wantCount: 25, wantMore: false,
			wantLimit: 10, wantOffset: 20,
		},
		{
			name: "offset beyond total", total: 5, limit: 10, offset: 100,
			wantStart: 5, wantEnd: 5, wantCount: 5, wantMore: false,
			wantLimit: 10, wantOffset: 100,
		},
		{
			name: "exact fit", total: 10, limit: 10, offset: 0,
			wantStart: 0, wantEnd: 10, wantCount: 10, wantMore: false,
			wantLimit: 10, wantOffset: 0,
		},
		{
			name: "empty collection", total: 0, limit: 10, offset: 0,
			wantStart: 0, wantEnd: 0, wantCount: 0, wantMore: false,
			wantLimit: 10, wantOffset: 0,
		},
		{
			name: "single item collection", total: 1, limit: 10, offset: 0,
			wantStart: 0, wantEnd: 1, wantCount: 1, wantMore: false,
			wantLimit: 10, wantOffset: 0,
		},
		{
			name: "offset at boundary", total: 20, limit: 10, offset: 10,
			wantStart: 10, wantEnd: 20, wantCount: 20, wantMore: false,
			wantLimit: 10, wantOffset: 10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, meta := paginateSlice(tt.total, tt.limit, tt.offset)
			assert.Equal(t, tt.wantStart, start, "start")
			assert.Equal(t, tt.wantEnd, end, "end")
			assert.Equal(t, tt.wantCount, meta.TotalCount, "total_count")
			assert.Equal(t, tt.wantMore, meta.HasMore, "has_more")
			assert.Equal(t, tt.wantLimit, meta.Limit, "limit")
			assert.Equal(t, tt.wantOffset, meta.Offset, "offset")

			// Invariant: start <= end <= total.
			assert.LessOrEqual(t, start, end)
			assert.LessOrEqual(t, end, tt.total)
		})
	}
}
