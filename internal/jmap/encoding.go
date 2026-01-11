package jmap

import (
	"encoding/json"
	"fmt"
)

// UnmarshalJSON implements custom unmarshaling for MethodCall
func (mc *MethodCall) UnmarshalJSON(data []byte) error {
	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	if len(arr) != 3 {
		return fmt.Errorf("method call must have 3 elements, got %d", len(arr))
	}

	if err := json.Unmarshal(arr[0], &mc.Name); err != nil {
		return fmt.Errorf("parsing method name: %w", err)
	}
	if err := json.Unmarshal(arr[1], &mc.Args); err != nil {
		return fmt.Errorf("parsing method args: %w", err)
	}
	if err := json.Unmarshal(arr[2], &mc.CallID); err != nil {
		return fmt.Errorf("parsing call ID: %w", err)
	}
	return nil
}

// MarshalJSON implements custom marshaling for MethodCall
func (mc MethodCall) MarshalJSON() ([]byte, error) {
	return json.Marshal([]any{mc.Name, mc.Args, mc.CallID})
}

// UnmarshalJSON implements custom unmarshaling for MethodResponse
func (mr *MethodResponse) UnmarshalJSON(data []byte) error {
	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	if len(arr) != 3 {
		return fmt.Errorf("method response must have 3 elements, got %d", len(arr))
	}

	if err := json.Unmarshal(arr[0], &mr.Name); err != nil {
		return fmt.Errorf("parsing method name: %w", err)
	}
	if err := json.Unmarshal(arr[1], &mr.Args); err != nil {
		return fmt.Errorf("parsing method args: %w", err)
	}
	if err := json.Unmarshal(arr[2], &mr.CallID); err != nil {
		return fmt.Errorf("parsing call ID: %w", err)
	}
	return nil
}

// MarshalJSON implements custom marshaling for MethodResponse
func (mr MethodResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal([]any{mr.Name, mr.Args, mr.CallID})
}
