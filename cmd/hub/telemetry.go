package main

import (
	"context"
	"encoding/xml"
	"log"
	"math"
	"sync/atomic"
	"time"

	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/southbound/device"
	"csip-tls-test/internal/southbound/registry"
	"csip-tls-test/internal/tlsclient"
)

// deviceMUP holds the single server-assigned MUP path for one device
// and tracks consecutive POST failures for re-registration.
type deviceMUP struct {
	name     string
	path     string
	failures int
}

const mupReregisterThreshold = 3

func telemetryLoop(
	ctx context.Context,
	cfg *Config,
	fetcher *tlsclient.WolfSSLFetcher,
	lfdi string,
	reg *registry.Registry,
	clockOffset *atomic.Int64,
	met *hubMetrics,
) {
	var allMUPs []deviceMUP
	for _, dc := range cfg.Devices {
		path, err := registerDeviceMUP(fetcher, lfdi, dc.Name, cfg.MUPPostRateS)
		if err != nil {
			log.Printf("hub: MUP registration for %s failed: %v — skipping", dc.Name, err)
			continue
		}
		allMUPs = append(allMUPs, deviceMUP{name: dc.Name, path: path})
	}
	if len(allMUPs) == 0 {
		log.Printf("hub: no MUPs registered — telemetry disabled")
		return
	}

	postTicker := time.NewTicker(cfg.MUPPostRate())
	defer postTicker.Stop()

	updates := reg.Updates()
	latest := make(map[string]device.Measurements)

	for {
		select {
		case <-ctx.Done():
			return

		case upd, ok := <-updates:
			if !ok {
				return
			}
			if upd.Err == nil {
				latest[upd.Name] = upd.Measurements
				met.recordMeasurement(upd.Name, upd.Measurements)
			} else {
				log.Printf("hub: device %s poll error: %v", upd.Name, upd.Err)
			}

		case <-postTicker.C:
			for i := range allMUPs {
				dm := &allMUPs[i]
				m, ok := latest[dm.name]
				if !ok {
					continue
				}
				postErr := postDeviceMeasurements(fetcher, dm.name, dm.path, m,
					clockOffset.Load(), cfg.MUPPostRateS)
				met.recordPost(dm.name, postErr)
				if postErr != nil {
					dm.failures++
					if dm.failures >= mupReregisterThreshold {
						log.Printf("hub: %d consecutive POST failures for %s; re-registering MUP",
							dm.failures, dm.name)
						newPath, rerr := registerDeviceMUP(fetcher, lfdi, dm.name, cfg.MUPPostRateS)
						if rerr != nil {
							log.Printf("hub: MUP re-registration for %s failed: %v", dm.name, rerr)
						} else {
							log.Printf("hub: MUP re-registered: %s → %s", dm.name, newPath)
							dm.path = newPath
							dm.failures = 0
						}
					}
				} else {
					dm.failures = 0
				}
			}
		}
	}
}

func registerDeviceMUP(fetcher *tlsclient.WolfSSLFetcher, lfdi, deviceName string, postRateS int) (string, error) {
	prefix := lfdi
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	mup := model.MirrorUsagePoint{
		MRID:                prefix + "-" + deviceName,
		Description:         deviceName + " Measurements (W/V/Hz)",
		RoleFlags:           0x0002,
		ServiceCategoryKind: 0,
		Status:              1,
		DeviceLFDI:          lfdi,
		PostRate:            uint32(postRateS),
	}
	body, err := xml.Marshal(&mup)
	if err != nil {
		return "", err
	}
	_, loc, err := fetcher.Post("/mup", body, "application/sep+xml")
	if err != nil {
		return "", err
	}
	log.Printf("hub: MUP registered: %s → %s", deviceName, loc)
	return loc, nil
}

func postDeviceMeasurements(
	fetcher *tlsclient.WolfSSLFetcher,
	deviceName string,
	mupPath string,
	m device.Measurements,
	clockOffset int64,
	intervalS int,
) error {
	now := time.Now().Unix() + clockOffset
	dur := uint32(intervalS)
	start := now - int64(dur)

	var readings []model.Reading
	if !math.IsNaN(m.W) {
		readings = append(readings, model.Reading{
			LocalID:    1,
			Value:      int64(math.Round(m.W)),
			TimePeriod: &model.DateTimeInterval{Start: start, Duration: dur},
		})
	}
	if !math.IsNaN(m.V) {
		readings = append(readings, model.Reading{
			LocalID:    2,
			Value:      int64(math.Round(m.V * 100)),
			TimePeriod: &model.DateTimeInterval{Start: start, Duration: dur},
		})
	}
	if !math.IsNaN(m.Hz) {
		readings = append(readings, model.Reading{
			LocalID:    3,
			Value:      int64(math.Round(m.Hz * 100)),
			TimePeriod: &model.DateTimeInterval{Start: start, Duration: dur},
		})
	}
	if len(readings) == 0 {
		return nil
	}

	mmr := model.MirrorMeterReading{
		MirrorReadingSet: []model.MirrorReadingSet{{
			StartTime: start,
			Duration:  dur,
			Reading:   readings,
		}},
	}
	body, err := xml.Marshal(&mmr)
	if err != nil {
		log.Printf("hub: marshal telemetry %s: %v", deviceName, err)
		return err
	}
	if _, _, err = fetcher.Post(mupPath, body, "application/sep+xml"); err != nil {
		log.Printf("hub: POST telemetry %s: %v", deviceName, err)
		return err
	}
	log.Printf("hub: telemetry posted: %s W=%.0f V=%.1f Hz=%.2f",
		deviceName, m.W, m.V, m.Hz)
	return nil
}
