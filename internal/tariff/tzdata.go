package tariff

// Embed the IANA timezone database so tariff.RateAt / BillCalc window math is
// hermetic on any host, regardless of whether system zoneinfo is installed
// (e.g. a minimal container in pure-go CI). This is standard-library only — it
// adds no module dependency — and correct TOU window resolution across
// timezones is core to this package's job, so the ~500 KB it adds is warranted.
import _ "time/tzdata"
