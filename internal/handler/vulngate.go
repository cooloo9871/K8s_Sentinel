package handler

import (
	"encoding/json"
	"net/http"

	"github.com/cooloo9871/K8s_Sentinel/internal/vulngate"
)

type vulnGateView struct {
	Settings vulngate.Settings `json:"settings"`
	Status   vulngate.Status   `json:"status"`
}

func getVulnGate(gate *vulngate.Gate) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, vulnGateView{Settings: gate.Settings(), Status: gate.Status()})
	}
}

func putVulnGate(gate *vulngate.Gate) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var s vulngate.Settings
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		if err := gate.Save(s); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, vulnGateView{Settings: gate.Settings(), Status: gate.Status()})
	}
}
