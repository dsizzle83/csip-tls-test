package gridsim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"csip-tls-test/internal/csip/model"
)

// AdminHandler returns a plain HTTP handler for the gridsim management API.
// Mount this on a separate port (default 11112) — it is NOT mTLS-protected.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/status", cors(s.handleAdminStatus))
	mux.HandleFunc("/admin/control", cors(s.handleAdminControl))
	return mux
}

func cors(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

type adminCtrlInfo struct {
	MRID        string `json:"mrid"`
	Description string `json:"description"`
	ExportLimW  int    `json:"export_limit_W"`
	Start       int64  `json:"start"`
	DurationS   int    `json:"duration_s"`
	Status      int    `json:"status"`
}

type adminProgInfo struct {
	ID          int             `json:"id"`
	MRID        string          `json:"mrid"`
	Description string          `json:"description"`
	Primacy     int             `json:"primacy"`
	Active      []adminCtrlInfo `json:"active"`
	Scheduled   []adminCtrlInfo `json:"scheduled"`
}

type adminStatusResp struct {
	Programs   []adminProgInfo `json:"programs"`
	ServerTime int64           `json:"server_time"`
}

var progMeta = []struct {
	MRID        string
	Description string
	Primacy     int
}{
	{"DERP-SP-001", "Service Point (primacy 1)", 1},
	{"DERP-SITE-001", "Site-Level (primacy 5)", 5},
	{"DERP-SYS-001", "System-Level (primacy 10)", 10},
}

func (s *Server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var programs []adminProgInfo
	for i, pm := range progMeta {
		ap := adminProgInfo{
			ID:          i,
			MRID:        pm.MRID,
			Description: pm.Description,
			Primacy:     pm.Primacy,
		}
		if actList, ok := s.resources[fmt.Sprintf("/derp/%d/actderc", i)].(*model.DERControlList); ok {
			for _, c := range actList.DERControl {
				ap.Active = append(ap.Active, ctrlToInfo(c))
			}
		}
		if schList, ok := s.resources[fmt.Sprintf("/derp/%d/derc", i)].(*model.DERControlList); ok {
			for _, c := range schList.DERControl {
				ap.Scheduled = append(ap.Scheduled, ctrlToInfo(c))
			}
		}
		programs = append(programs, ap)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(adminStatusResp{
		Programs:   programs,
		ServerTime: time.Now().Unix(),
	})
}

func ctrlToInfo(c model.DERControl) adminCtrlInfo {
	info := adminCtrlInfo{
		MRID:        c.MRID,
		Description: c.Description,
		Start:       c.Interval.Start,
		DurationS:   int(c.Interval.Duration),
	}
	if c.EventStatus != nil {
		info.Status = int(c.EventStatus.CurrentStatus)
	}
	if c.DERControlBase.OpModExpLimW != nil {
		info.ExportLimW = int(c.DERControlBase.OpModExpLimW.Value)
	}
	return info
}

type adminCtrlReq struct {
	Program     int    `json:"program"`
	Description string `json:"description"`
	ExportLimW  int    `json:"export_limit_W"`
	StartOffset int    `json:"start_offset_s"`
	DurationS   int    `json:"duration_s"`
	Activate    bool   `json:"activate"`
}

func (s *Server) handleAdminControl(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.adminCtrlPost(w, r)
	case http.MethodDelete:
		s.adminCtrlDelete(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

var progPrefixes = []string{"SP", "SITE", "SYS"}

func (s *Server) adminCtrlPost(w http.ResponseWriter, r *http.Request) {
	var req adminCtrlReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Program < 0 || req.Program > 2 {
		http.Error(w, "program must be 0, 1, or 2", http.StatusBadRequest)
		return
	}
	if req.DurationS <= 0 {
		req.DurationS = 300
	}
	if req.Description == "" {
		req.Description = "Admin control"
	}

	now := time.Now().Unix()
	ctrl := model.DERControl{
		Resource:     model.Resource{Href: fmt.Sprintf("/derp/%d/actderc/admin", req.Program)},
		MRID:         fmt.Sprintf("DERC-%s-ADMIN-%d", progPrefixes[req.Program], now),
		Description:  req.Description,
		CreationTime: now,
		EventStatus: &model.EventStatus{
			CurrentStatus: 1, // Active
			DateTime:      now,
		},
		Interval: model.DateTimeInterval{
			Duration: uint32(req.DurationS),
			Start:    now + int64(req.StartOffset),
		},
		DERControlBase: model.DERControlBase{
			OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: int16(req.ExportLimW)},
		},
	}

	// Also set ctrl href to the derc path so the walker finds it.
	ctrl.Resource.Href = fmt.Sprintf("/derp/%d/derc/admin", req.Program)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Write to derc (scheduled list) — this is what the hub's walker reads via
	// DERControlListLink. The scheduler evaluates the time window and marks it
	// active when start <= serverNow < start+duration.
	dercPath := fmt.Sprintf("/derp/%d/derc", req.Program)
	if dercList, ok := s.resources[dercPath].(*model.DERControlList); ok {
		if req.Activate {
			dercList.DERControl = []model.DERControl{ctrl}
		} else {
			dercList.DERControl = append(dercList.DERControl, ctrl)
		}
		dercList.All = uint32(len(dercList.DERControl))
		dercList.Results = dercList.All
	}

	// Also mirror into actderc for status display.
	actPath := fmt.Sprintf("/derp/%d/actderc", req.Program)
	if actList, ok := s.resources[actPath].(*model.DERControlList); ok {
		if req.Activate {
			actList.DERControl = []model.DERControl{ctrl}
		} else {
			actList.DERControl = append(actList.DERControl, ctrl)
		}
		actList.All = uint32(len(actList.DERControl))
		actList.Results = actList.All
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) adminCtrlDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Program int `json:"program"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Program < 0 || req.Program > 2 {
		http.Error(w, "program must be 0, 1, or 2", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, path := range []string{
		fmt.Sprintf("/derp/%d/derc", req.Program),
		fmt.Sprintf("/derp/%d/actderc", req.Program),
	} {
		if list, ok := s.resources[path].(*model.DERControlList); ok {
			list.DERControl = nil
			list.All = 0
			list.Results = 0
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
