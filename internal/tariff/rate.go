package tariff

import "time"

// RateAt reports the rate structure in effect at ts. ts may be in any location;
// it is converted to the tariff's timezone before any window math (so a UTC
// instant resolves against the correct local season/day/period).
//
// ImportUSDPerKWh = period energy rate + riders (tier adders are monthly state,
// applied only in BillCalc). ExportUSDPerKWh depends on export type: for
// net_metering it is the bare period energy rate (no riders, no tier adder);
// for buyback the flat export rate; for none it is 0.
//
// If ts somehow resolves to no period (impossible for a validated tariff, whose
// periods tile the whole week), the zero RateInfo is returned.
func (t *Tariff) RateAt(ts time.Time) RateInfo {
	p, ok := t.periodAt(ts.In(t.location()))
	if !ok {
		return RateInfo{}
	}
	ri := RateInfo{
		PeriodID:        p.ID,
		PeriodLabel:     p.Label,
		ImportUSDPerKWh: p.RateUSDPerKWh + t.RidersUSDPerKWh,
	}
	switch t.Export.Type {
	case ExportNetMetering:
		ri.ExportUSDPerKWh = p.RateUSDPerKWh
	case ExportBuyback:
		ri.ExportUSDPerKWh = t.Export.RateUSDPerKWh
	case ExportNone:
		ri.ExportUSDPerKWh = 0
	}
	return ri
}

// periodAt resolves the season/day_type/period covering a local (tariff-TZ)
// instant. local MUST already be in t.location(). The bool is false only if no
// season/day/period matches — which a validated tariff makes impossible.
func (t *Tariff) periodAt(local time.Time) (Period, bool) {
	month := int(local.Month())
	wd := local.Weekday()
	minute := local.Hour()*60 + local.Minute()

	for si := range t.Energy.Seasons {
		s := &t.Energy.Seasons[si]
		if !containsInt(s.Months, month) {
			continue
		}
		for di := range s.DayTypes {
			dt := &s.DayTypes[di]
			wds, err := expandDays(dt.Days)
			if err != nil || !containsWeekday(wds, wd) {
				continue
			}
			for pi := range dt.Periods {
				p := dt.Periods[pi]
				if minuteInWindow(minute, mustHM(p.Start), mustHM(p.End)) {
					return p, true
				}
			}
		}
	}
	return Period{}, false
}
