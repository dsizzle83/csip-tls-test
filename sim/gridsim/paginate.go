package gridsim

// paginate.go — positive list-pagination mode (QA fault injection, default OFF).
// Audit docs/QA_COMPLETENESS_AUDIT.md P1-1.
//
// When armed (POST /admin/paginate {"page_size":N}), GETs of a 2030.5 LIST
// resource honor the s (start offset) and l (limit) query parameters and serve
// only that page, with all=<full count> and results=<page count> — so a
// spec-compliant client MUST walk multiple pages (?s=<offset>) to collect every
// entry. Disarmed (page_size 0 / {"clear":true}) every list serves whole,
// exactly as before (this sim's historical single-response behaviour).
//
// This is the POSITIVE twin of malform.go's MalformPagination, which lies
// all=999 to bait a naive pager: here all/results are HONEST and the extra
// pages are REAL, so a client that fails to page silently sees only the first
// page's entries — the exact P1-1 field failure ("utility returns all=40,
// results=10 → hub obeys only the first 10 programs/controls").
//
// An optional path filter scopes pagination to ONE list (e.g. just
// "/derp/0/derc") so a scenario can page a single list without perturbing the
// rest of the walk; an empty path pages every paginatable list.
//
// Default behaviour is unchanged: with page_size == 0 applyPagination is a cheap
// no-op that returns the resource untouched.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	model "lexa-proto/csipmodel"
)

// paginateState is the armed pagination configuration. Zero value
// (pageSize == 0) means disarmed.
type paginateState struct {
	pageSize int    // max entries per served page; 0 ⇒ disarmed
	path     string // only this list path is paged; "" ⇒ every paginatable list
}

// SetPaginate arms (pageSize > 0) or disarms (pageSize <= 0) positive
// pagination. path scopes it to one list resource; "" ⇒ all lists.
func (s *Server) SetPaginate(pageSize int, path string) {
	s.paginateMu.Lock()
	if pageSize <= 0 {
		s.paginate = paginateState{}
	} else {
		s.paginate = paginateState{pageSize: pageSize, path: path}
	}
	s.paginateMu.Unlock()
}

// applyPagination returns a page-sliced COPY of a list resource per the s/l
// query when pagination is armed for path, or resource unchanged otherwise
// (disarmed, a non-matching path, or a non-list resource). `all` on the copy is
// always the FULL entry count and `results` the slice count. The stored
// resource is never mutated — only a shallow copy with a sub-slice is returned.
func (s *Server) applyPagination(path string, resource interface{}, query url.Values) interface{} {
	s.paginateMu.Lock()
	st := s.paginate
	s.paginateMu.Unlock()

	if st.pageSize == 0 {
		return resource
	}
	if st.path != "" && st.path != path {
		return resource
	}
	start := parseUintQuery(query, "s")
	limit := parseUintQuery(query, "l")
	if limit == 0 || limit > st.pageSize {
		limit = st.pageSize // the client's l is a hint; the server caps it at its page size
	}
	return pageResource(resource, start, limit)
}

// pageSlice returns entries[start:start+limit] (clamped) plus the full count and
// the slice count, for any list entry type.
func pageSlice[E any](entries []E, start, limit int) (sub []E, all, results int) {
	all = len(entries)
	lo := start
	if lo > all {
		lo = all
	}
	hi := lo + limit
	if hi > all {
		hi = all
	}
	return entries[lo:hi], all, hi - lo
}

// pageResource returns a shallow copy of a paginatable list resource holding
// only the [start, start+limit) page, with all/results set accordingly. Any
// non-list resource (DeviceCapability, Time, a DefaultDERControl, …) passes
// through unchanged. Covers exactly the list types the hub walker pages
// (EndDeviceList, DERProgramList, DERControlList/ExtendedDERControlList,
// MirrorUsagePointList) plus FSA/DER lists for completeness.
func pageResource(resource interface{}, start, limit int) interface{} {
	switch l := resource.(type) {
	case *model.EndDeviceList:
		sub, all, res := pageSlice(l.EndDevice, start, limit)
		c := *l
		c.EndDevice, c.All, c.Results = sub, uint32(all), uint32(res)
		return &c
	case *model.DERProgramList:
		sub, all, res := pageSlice(l.DERProgram, start, limit)
		c := *l
		c.DERProgram, c.All, c.Results = sub, uint32(all), uint32(res)
		return &c
	case *model.DERControlList:
		sub, all, res := pageSlice(l.DERControl, start, limit)
		c := *l
		c.DERControl, c.All, c.Results = sub, uint32(all), uint32(res)
		return &c
	case *model.ExtendedDERControlList:
		sub, all, res := pageSlice(l.DERControl, start, limit)
		c := *l
		c.DERControl, c.All, c.Results = sub, uint32(all), uint32(res)
		return &c
	case *model.MirrorUsagePointList:
		sub, all, res := pageSlice(l.MirrorUsagePoint, start, limit)
		c := *l
		c.MirrorUsagePoint, c.All, c.Results = sub, uint32(all), uint32(res)
		return &c
	case *model.FunctionSetAssignmentsList:
		sub, all, res := pageSlice(l.FunctionSetAssignments, start, limit)
		c := *l
		c.FunctionSetAssignments, c.All, c.Results = sub, uint32(all), uint32(res)
		return &c
	case *model.DERList:
		sub, all, res := pageSlice(l.DER, start, limit)
		c := *l
		c.DER, c.All, c.Results = sub, uint32(all), uint32(res)
		return &c
	default:
		return resource
	}
}

// parseUintQuery reads a non-negative integer query parameter, defaulting to 0
// on absence or a bad value.
func parseUintQuery(q url.Values, key string) int {
	if v, err := strconv.Atoi(q.Get(key)); err == nil && v >= 0 {
		return v
	}
	return 0
}

// adminPaginateReq is the body for POST /admin/paginate.
type adminPaginateReq struct {
	PageSize int    `json:"page_size"`      // entries per page; 0/clear disarms
	Path     string `json:"path,omitempty"` // scope to one list; "" ⇒ all lists
	Clear    bool   `json:"clear"`
}

// handleAdminPaginate is POST /admin/paginate. Arm with
// {"page_size":1,"path":"/derp/0/derc"}; disarm with {"clear":true}.
func (s *Server) handleAdminPaginate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req adminPaginateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ps := req.PageSize
	if req.Clear {
		ps = 0
	}
	s.SetPaginate(ps, req.Path)
	w.WriteHeader(http.StatusNoContent)
}
