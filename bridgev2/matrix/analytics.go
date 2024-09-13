package matrix

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"maunium.net/go/mautrix/id"
)

func (br *Connector) trackSync(userID id.UserID, event string, properties map[string]any) error {
	var buf bytes.Buffer
	var analyticsUserID string
	if br.Config.Analytics.UserID != "" {
		analyticsUserID = br.Config.Analytics.UserID
	} else {
		analyticsUserID = userID.String()
	}
	err := json.NewEncoder(&buf).Encode(map[string]any{
		"userId":     analyticsUserID,
		"event":      event,
		"properties": properties,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, br.Config.Analytics.URL, &buf)
	if err != nil {
		return err
	}
	req.SetBasicAuth(br.Config.Analytics.Token, "")
	resp, err := br.AS.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	return nil
}

func (br *Connector) TrackAnalytics(userID id.UserID, event string, props map[string]any) {
	if br.Config.Analytics.Token == "" || br.Config.Analytics.URL == "" {
		return
	}

	if props == nil {
		props = map[string]any{}
	}
	props["bridge"] = br.Bridge.Network.GetName().BeeperBridgeType
	go func() {
		err := br.trackSync(userID, event, props)
		if err != nil {
			br.Log.Err(err).Str("component", "analytics").Str("event", event).Msg("Error tracking event")
		} else {
			br.Log.Debug().Str("component", "analytics").Str("event", event).Msg("Tracked event")
		}
	}()
}
