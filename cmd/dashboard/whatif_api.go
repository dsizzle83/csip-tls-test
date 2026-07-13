package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"csip-tls-test/internal/scenariodata"
	"csip-tls-test/internal/tariff"
	"csip-tls-test/internal/whatif"
)

// registerWhatif wires the dashboard V2 what-if engine endpoints onto mux
// (CONTRACTS.md §3). Datasets and tariffs are loaded fresh from disk on every
// request — they are small, and reloading keeps the handlers stateless and
// therefore concurrency-safe by construction (no shared mutable state, so a
// sibling that regenerates data/ is picked up without a restart).
//
// main.go wires the call at integration; this file owns only the handlers.
func registerWhatif(mux *http.ServeMux, scenarioDir, tariffDir string) {
	mux.HandleFunc("/api/whatif/run", func(w http.ResponseWriter, r *http.Request) {
		handleWhatifRun(w, r, scenarioDir, tariffDir)
	})
	mux.HandleFunc("/api/scenarios", func(w http.ResponseWriter, r *http.Request) {
		handleScenarios(w, r, scenarioDir)
	})
	mux.HandleFunc("/api/tariffs", func(w http.ResponseWriter, r *http.Request) {
		handleTariffs(w, r, tariffDir)
	})
}

// whatifRunRequest is the POST /api/whatif/run body (CONTRACTS.md §3).
type whatifRunRequest struct {
	ScenarioID  string          `json:"scenario_id"`
	TariffIDs   []string        `json:"tariff_ids"`
	Instruments json.RawMessage `json:"instruments"` // optional partial override
	Policies    []string        `json:"policies"`    // optional; default all three
}

func handleWhatifRun(w http.ResponseWriter, r *http.Request, scenarioDir, tariffDir string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req whatifRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}
	if req.ScenarioID == "" {
		writeErr(w, http.StatusBadRequest, "scenario_id is required")
		return
	}
	if len(req.TariffIDs) < 1 || len(req.TariffIDs) > 4 {
		writeErr(w, http.StatusBadRequest, "tariff_ids must contain between 1 and 4 ids")
		return
	}

	scenarios, err := scenariodata.Load(scenarioDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load scenarios: "+err.Error())
		return
	}
	tariffs, err := tariff.Load(tariffDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load tariffs: "+err.Error())
		return
	}

	sc, ok := scenarios[req.ScenarioID]
	if !ok {
		writeErr(w, http.StatusBadRequest, "unknown scenario_id: "+req.ScenarioID)
		return
	}
	tarList := make([]*tariff.Tariff, 0, len(req.TariffIDs))
	for _, id := range req.TariffIDs {
		t, ok := tariffs[id]
		if !ok {
			writeErr(w, http.StatusBadRequest, "unknown tariff_id: "+id)
			return
		}
		tarList = append(tarList, t)
	}

	inst, err := mergeInstruments(sc.Meta.InstrumentDefaults, req.Instruments)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad instruments: "+err.Error())
		return
	}

	resp, err := whatif.Run(sc, tarList, inst, req.Policies)
	if err != nil {
		var cv *whatif.CrossValError
		var ie *whatif.InputError
		switch {
		case errors.As(err, &cv):
			writeErr(w, http.StatusUnprocessableEntity, cv.Error())
		case errors.As(err, &ie):
			writeErr(w, http.StatusBadRequest, ie.Error())
		default:
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleScenarios returns every scenario's scenario.json echo (CONTRACTS.md §3).
func handleScenarios(w http.ResponseWriter, r *http.Request, scenarioDir string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	scenarios, err := scenariodata.Load(scenarioDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load scenarios: "+err.Error())
		return
	}
	out := make([]scenariodata.Meta, 0, len(scenarios))
	for _, sc := range scenarios {
		out = append(out, sc.Meta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, http.StatusOK, out)
}

// handleTariffs returns the tariffs for a territory (or all, if no filter).
func handleTariffs(w http.ResponseWriter, r *http.Request, tariffDir string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tariffs, err := tariff.Load(tariffDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load tariffs: "+err.Error())
		return
	}
	territory := r.URL.Query().Get("territory")
	out := make([]*tariff.Tariff, 0, len(tariffs))
	for _, t := range tariffs {
		if territory != "" && t.Territory != territory {
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, http.StatusOK, out)
}

// mergeInstruments deep-merges an optional partial instruments override (from
// the request) onto the scenario's instrument defaults. Any-depth override:
// send only pv_kw and every other field keeps its scenario default.
func mergeInstruments(defaults scenariodata.InstrumentDefaults, overlay json.RawMessage) (whatif.Instruments, error) {
	baseBytes, err := json.Marshal(defaults)
	if err != nil {
		return whatif.Instruments{}, err
	}
	var baseMap map[string]any
	if err := json.Unmarshal(baseBytes, &baseMap); err != nil {
		return whatif.Instruments{}, err
	}
	if len(overlay) > 0 && string(overlay) != "null" {
		var ov map[string]any
		if err := json.Unmarshal(overlay, &ov); err != nil {
			return whatif.Instruments{}, err
		}
		deepMerge(baseMap, ov)
	}
	mergedBytes, err := json.Marshal(baseMap)
	if err != nil {
		return whatif.Instruments{}, err
	}
	var inst whatif.Instruments
	if err := json.Unmarshal(mergedBytes, &inst); err != nil {
		return whatif.Instruments{}, err
	}
	return inst, nil
}

// deepMerge recursively merges src into dst (nested objects merge; scalars and
// arrays overwrite).
func deepMerge(dst, src map[string]any) {
	for k, v := range src {
		if vm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				deepMerge(dm, vm)
				continue
			}
		}
		dst[k] = v
	}
}

// writeJSON writes v as an application/json response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr writes a JSON error envelope {"error": msg} with the given status.
func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
