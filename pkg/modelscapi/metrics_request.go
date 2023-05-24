// Code generated by go-swagger; DO NOT EDIT.

package modelscapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// MetricsRequest metrics
//
// push metrics model
//
// swagger:model MetricsRequest
type MetricsRequest struct {

	// bouncers
	// Required: true
	Bouncers []*MetricsRequestBouncersItem `json:"bouncers"`

	// machines
	// Required: true
	Machines []*MetricsRequestMachinesItem `json:"machines"`
}

// Validate validates this metrics request
func (m *MetricsRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBouncers(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMachines(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *MetricsRequest) validateBouncers(formats strfmt.Registry) error {

	if err := validate.Required("bouncers", "body", m.Bouncers); err != nil {
		return err
	}

	for i := 0; i < len(m.Bouncers); i++ {
		if swag.IsZero(m.Bouncers[i]) { // not required
			continue
		}

		if m.Bouncers[i] != nil {
			if err := m.Bouncers[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("bouncers" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("bouncers" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *MetricsRequest) validateMachines(formats strfmt.Registry) error {

	if err := validate.Required("machines", "body", m.Machines); err != nil {
		return err
	}

	for i := 0; i < len(m.Machines); i++ {
		if swag.IsZero(m.Machines[i]) { // not required
			continue
		}

		if m.Machines[i] != nil {
			if err := m.Machines[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("machines" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("machines" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this metrics request based on the context it is used
func (m *MetricsRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateBouncers(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMachines(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *MetricsRequest) contextValidateBouncers(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Bouncers); i++ {

		if m.Bouncers[i] != nil {
			if err := m.Bouncers[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("bouncers" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("bouncers" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *MetricsRequest) contextValidateMachines(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Machines); i++ {

		if m.Machines[i] != nil {
			if err := m.Machines[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("machines" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("machines" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *MetricsRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MetricsRequest) UnmarshalBinary(b []byte) error {
	var res MetricsRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}