package dbutil

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// JSON is a utility type for using arbitrary JSON data as values in database Exec and Scan calls.
type JSON struct {
	Data any
}

func (j JSON) Scan(i any) error {
	switch value := i.(type) {
	case nil:
		return nil
	case string:
		return json.Unmarshal([]byte(value), j.Data)
	case []byte:
		return json.Unmarshal(value, j.Data)
	default:
		return fmt.Errorf("invalid type %T for dbutil.JSON.Scan", i)
	}
}

func (j JSON) Value() (driver.Value, error) {
	if j.Data == nil {
		return nil, nil
	}
	v, err := json.Marshal(j.Data)
	return string(v), err
}
