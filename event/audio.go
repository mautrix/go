package event

type MSC1767Audio struct {
	Duration int   `json:"duration"`
	Waveform []int `json:"waveform"`
}

type MSC3245Voice struct{}
