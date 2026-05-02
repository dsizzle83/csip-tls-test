package main

import (
	"encoding/xml"
	"log"

	"csip-tls-test/internal/csip/discovery"
	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/csip/scheduler"
	"csip-tls-test/internal/tlsclient"
)

// responseTracker implements the GEN.044 / CORE-022 response POST state
// machine: Received(1) → Started(2) → Completed(3).
type responseTracker struct {
	fetcher         *tlsclient.WolfSSLFetcher
	lfdi            string
	responseSetPath string
	clockOffset     int64

	received   map[string]bool // event MRIDs for which we have sent Received(1)
	activeMRID string          // MRID of the event we last sent Started(2) for
}

func newResponseTracker(fetcher *tlsclient.WolfSSLFetcher, lfdi, responseSetPath string) *responseTracker {
	return &responseTracker{
		fetcher:         fetcher,
		lfdi:            lfdi,
		responseSetPath: responseSetPath,
		received:        make(map[string]bool),
	}
}

func (rt *responseTracker) update(tree *discovery.ResourceTree, active *scheduler.ActiveControl) {
	rt.clockOffset = tree.ClockOffset

	for _, ps := range tree.Programs {
		if ps.Controls == nil {
			continue
		}
		for _, ctrl := range ps.Controls.DERControl {
			if ctrl.EventStatus != nil && ctrl.EventStatus.CurrentStatus == 6 {
				continue
			}
			if !rt.received[ctrl.MRID] {
				rt.post(ctrl.MRID, model.ResponseEventReceived)
				rt.received[ctrl.MRID] = true
			}
		}
	}

	if active == nil || active.Source == "default" {
		if rt.activeMRID != "" {
			rt.post(rt.activeMRID, model.ResponseEventCompleted)
			rt.activeMRID = ""
		}
		return
	}

	if active.MRID != rt.activeMRID {
		if rt.activeMRID != "" {
			rt.post(rt.activeMRID, model.ResponseEventCompleted)
		}
		rt.post(active.MRID, model.ResponseEventStarted)
		rt.activeMRID = active.MRID
	}

	if active.ValidUntil > 0 && scheduler.ServerNow(tree.ClockOffset) >= active.ValidUntil {
		rt.post(active.MRID, model.ResponseEventCompleted)
		rt.activeMRID = ""
	}
}

func (rt *responseTracker) post(mrid string, status uint8) {
	resp := model.Response{
		CreatedDateTime: scheduler.ServerNow(rt.clockOffset),
		EndDeviceLFDI:   rt.lfdi,
		Status:          status,
		Subject:         mrid,
	}
	body, err := xml.Marshal(&resp)
	if err != nil {
		log.Printf("hub: marshal Response: %v", err)
		return
	}
	if _, _, err = rt.fetcher.Post(rt.responseSetPath, body, "application/sep+xml"); err != nil {
		log.Printf("hub: POST response (mrid=%s status=%d): %v", mrid, status, err)
		return
	}
	statusName := map[uint8]string{1: "Received", 2: "Started", 3: "Completed"}[status]
	log.Printf("hub: response posted: %s mrid=%s", statusName, mrid)
}
