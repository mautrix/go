package event

import "encoding/json"

type BeeperButtonAction string

const (
	BeeperButtonActionPress       BeeperButtonAction = "press"
	BeeperButtonActionLink        BeeperButtonAction = "link"
	BeeperButtonActionCall        BeeperButtonAction = "call"
	BeeperButtonActionCopy        BeeperButtonAction = "copy"
	BeeperButtonActionList        BeeperButtonAction = "list"
	BeeperButtonActionInput       BeeperButtonAction = "input"
	BeeperButtonActionUnsupported BeeperButtonAction = "unsupported"
	BeeperButtonActionCallback    BeeperButtonAction = "callback"
)

type BeeperButtonStyle string

const (
	BeeperButtonStylePrimary BeeperButtonStyle = "primary"
	BeeperButtonStyleDanger  BeeperButtonStyle = "danger"
	BeeperButtonStyleSuccess BeeperButtonStyle = "success"
)

type BeeperButton struct {
	ID          string             `json:"id"`
	Label       string             `json:"label"`
	Action      BeeperButtonAction `json:"action"`
	URL         string             `json:"url,omitempty"`
	Phone       string             `json:"phone,omitempty"`
	Text        string             `json:"text,omitempty"`
	List        *BeeperButtonList  `json:"list,omitempty"`
	Placeholder string             `json:"placeholder,omitempty"`
	Row         *int               `json:"row,omitempty"`
	Style       BeeperButtonStyle  `json:"style,omitempty"`
	Disabled    bool               `json:"disabled,omitzero"`
	Icon        *BeeperButtonIcon  `json:"icon,omitempty"`
}

type BeeperButtonIcon struct {
	SF       string `json:"sf,omitempty"`
	Material string `json:"material,omitempty"`
}

type BeeperButtonList struct {
	Title    string                    `json:"title,omitempty"`
	Multiple bool                      `json:"multiple"`
	Min      *int                      `json:"min,omitempty"`
	Max      *int                      `json:"max,omitempty"`
	Custom   bool                      `json:"custom,omitzero"`
	Sections []BeeperButtonListSection `json:"sections"`
}

type BeeperButtonListSection struct {
	Title   string                   `json:"title,omitempty"`
	Options []BeeperButtonListOption `json:"options"`
}

type BeeperButtonListOption struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

type BeeperButtonsFallback struct {
	Body string `json:"body,omitempty"`
	HTML string `json:"html,omitempty"`
}

type BeeperPressButtonEventContent struct {
	RelatesTo RelatesTo `json:"m.relates_to"`
	ButtonID  string    `json:"button_id"`
	OptionIDs []string  `json:"option_ids,omitempty"`
	Text      string    `json:"text,omitempty"`
}

func (content *BeeperPressButtonEventContent) UnmarshalJSON(data []byte) error {
	type pressContent BeeperPressButtonEventContent
	var parsed pressContent
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}
	*content = BeeperPressButtonEventContent(parsed)
	return nil
}

func (content *BeeperPressButtonEventContent) GetRelatesTo() *RelatesTo {
	return &content.RelatesTo
}

func (content *BeeperPressButtonEventContent) OptionalGetRelatesTo() *RelatesTo {
	return &content.RelatesTo
}

func (content *BeeperPressButtonEventContent) SetRelatesTo(rel *RelatesTo) {
	content.RelatesTo = *rel
}

type BeeperButtonAnswer struct {
	Text  string `json:"text,omitempty"`
	Alert bool   `json:"alert,omitzero"`
	URL   string `json:"url,omitempty"`
}
