package event

type MSC1767Audio struct {
	Duration int   `json:"duration,omitempty"`
	Waveform []int `json:"waveform,omitempty"`
}

type MSC3245Voice struct{}
