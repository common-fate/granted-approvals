package genv

import (
	"context"
	"encoding/json"
)

// JSONLoader loads configuration from a serialized JSON payload
// set in the 'Data' field.
type JSONLoader struct {
	Data []byte
}

func (l JSONLoader) Load(ctx context.Context) (map[string]string, error) {
	var res map[string]string

	err := json.Unmarshal(l.Data, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}
