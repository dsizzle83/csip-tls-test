package adapters

import "csip-tls-test/internal/orchestrator"

// CompositeSystemReader merges Modbus registry state with OCPP EVSE state.
// OCPP may be nil when no EVSE server is configured; EVSEs will be empty in that case.
type CompositeSystemReader struct {
	Registry *RegistryAdapter
	OCPP     *OCPPStateTracker
}

func (r *CompositeSystemReader) ReadSystemState() (orchestrator.SystemState, error) {
	state, err := r.Registry.ReadSystemState()
	if err != nil {
		return state, err
	}
	if r.OCPP != nil {
		state.EVSEs = r.OCPP.EVSEStates()
	}
	return state, nil
}
