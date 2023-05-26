// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/asians-cloud/crowdsec/pkg/database/ent/alert"
	"github.com/asians-cloud/crowdsec/pkg/database/ent/machine"
)

// Alert is the model entity for the Alert schema.
type Alert struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt *time.Time `json:"created_at,omitempty"`
	// UpdatedAt holds the value of the "updated_at" field.
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	// Scenario holds the value of the "scenario" field.
	Scenario string `json:"scenario,omitempty"`
	// BucketId holds the value of the "bucketId" field.
	BucketId string `json:"bucketId,omitempty"`
	// Message holds the value of the "message" field.
	Message string `json:"message,omitempty"`
	// EventsCount holds the value of the "eventsCount" field.
	EventsCount int32 `json:"eventsCount,omitempty"`
	// StartedAt holds the value of the "startedAt" field.
	StartedAt time.Time `json:"startedAt,omitempty"`
	// StoppedAt holds the value of the "stoppedAt" field.
	StoppedAt time.Time `json:"stoppedAt,omitempty"`
	// SourceIp holds the value of the "sourceIp" field.
	SourceIp string `json:"sourceIp,omitempty"`
	// SourceRange holds the value of the "sourceRange" field.
	SourceRange string `json:"sourceRange,omitempty"`
	// SourceAsNumber holds the value of the "sourceAsNumber" field.
	SourceAsNumber string `json:"sourceAsNumber,omitempty"`
	// SourceAsName holds the value of the "sourceAsName" field.
	SourceAsName string `json:"sourceAsName,omitempty"`
	// SourceCountry holds the value of the "sourceCountry" field.
	SourceCountry string `json:"sourceCountry,omitempty"`
	// SourceLatitude holds the value of the "sourceLatitude" field.
	SourceLatitude float32 `json:"sourceLatitude,omitempty"`
	// SourceLongitude holds the value of the "sourceLongitude" field.
	SourceLongitude float32 `json:"sourceLongitude,omitempty"`
	// SourceScope holds the value of the "sourceScope" field.
	SourceScope string `json:"sourceScope,omitempty"`
	// SourceValue holds the value of the "sourceValue" field.
	SourceValue string `json:"sourceValue,omitempty"`
	// Capacity holds the value of the "capacity" field.
	Capacity int32 `json:"capacity,omitempty"`
	// LeakSpeed holds the value of the "leakSpeed" field.
	LeakSpeed string `json:"leakSpeed,omitempty"`
	// ScenarioVersion holds the value of the "scenarioVersion" field.
	ScenarioVersion string `json:"scenarioVersion,omitempty"`
	// ScenarioHash holds the value of the "scenarioHash" field.
	ScenarioHash string `json:"scenarioHash,omitempty"`
	// Simulated holds the value of the "simulated" field.
	Simulated bool `json:"simulated,omitempty"`
	// UUID holds the value of the "uuid" field.
	UUID string `json:"uuid,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the AlertQuery when eager-loading is set.
	Edges          AlertEdges `json:"edges"`
	machine_alerts *int
}

// AlertEdges holds the relations/edges for other nodes in the graph.
type AlertEdges struct {
	// Owner holds the value of the owner edge.
	Owner *Machine `json:"owner,omitempty"`
	// Decisions holds the value of the decisions edge.
	Decisions []*Decision `json:"decisions,omitempty"`
	// Events holds the value of the events edge.
	Events []*Event `json:"events,omitempty"`
	// Metas holds the value of the metas edge.
	Metas []*Meta `json:"metas,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [4]bool
}

// OwnerOrErr returns the Owner value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e AlertEdges) OwnerOrErr() (*Machine, error) {
	if e.loadedTypes[0] {
		if e.Owner == nil {
			// Edge was loaded but was not found.
			return nil, &NotFoundError{label: machine.Label}
		}
		return e.Owner, nil
	}
	return nil, &NotLoadedError{edge: "owner"}
}

// DecisionsOrErr returns the Decisions value or an error if the edge
// was not loaded in eager-loading.
func (e AlertEdges) DecisionsOrErr() ([]*Decision, error) {
	if e.loadedTypes[1] {
		return e.Decisions, nil
	}
	return nil, &NotLoadedError{edge: "decisions"}
}

// EventsOrErr returns the Events value or an error if the edge
// was not loaded in eager-loading.
func (e AlertEdges) EventsOrErr() ([]*Event, error) {
	if e.loadedTypes[2] {
		return e.Events, nil
	}
	return nil, &NotLoadedError{edge: "events"}
}

// MetasOrErr returns the Metas value or an error if the edge
// was not loaded in eager-loading.
func (e AlertEdges) MetasOrErr() ([]*Meta, error) {
	if e.loadedTypes[3] {
		return e.Metas, nil
	}
	return nil, &NotLoadedError{edge: "metas"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Alert) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case alert.FieldSimulated:
			values[i] = new(sql.NullBool)
		case alert.FieldSourceLatitude, alert.FieldSourceLongitude:
			values[i] = new(sql.NullFloat64)
		case alert.FieldID, alert.FieldEventsCount, alert.FieldCapacity:
			values[i] = new(sql.NullInt64)
		case alert.FieldScenario, alert.FieldBucketId, alert.FieldMessage, alert.FieldSourceIp, alert.FieldSourceRange, alert.FieldSourceAsNumber, alert.FieldSourceAsName, alert.FieldSourceCountry, alert.FieldSourceScope, alert.FieldSourceValue, alert.FieldLeakSpeed, alert.FieldScenarioVersion, alert.FieldScenarioHash, alert.FieldUUID:
			values[i] = new(sql.NullString)
		case alert.FieldCreatedAt, alert.FieldUpdatedAt, alert.FieldStartedAt, alert.FieldStoppedAt:
			values[i] = new(sql.NullTime)
		case alert.ForeignKeys[0]: // machine_alerts
			values[i] = new(sql.NullInt64)
		default:
			return nil, fmt.Errorf("unexpected column %q for type Alert", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Alert fields.
func (a *Alert) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case alert.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			a.ID = int(value.Int64)
		case alert.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				a.CreatedAt = new(time.Time)
				*a.CreatedAt = value.Time
			}
		case alert.FieldUpdatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field updated_at", values[i])
			} else if value.Valid {
				a.UpdatedAt = new(time.Time)
				*a.UpdatedAt = value.Time
			}
		case alert.FieldScenario:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field scenario", values[i])
			} else if value.Valid {
				a.Scenario = value.String
			}
		case alert.FieldBucketId:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field bucketId", values[i])
			} else if value.Valid {
				a.BucketId = value.String
			}
		case alert.FieldMessage:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field message", values[i])
			} else if value.Valid {
				a.Message = value.String
			}
		case alert.FieldEventsCount:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field eventsCount", values[i])
			} else if value.Valid {
				a.EventsCount = int32(value.Int64)
			}
		case alert.FieldStartedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field startedAt", values[i])
			} else if value.Valid {
				a.StartedAt = value.Time
			}
		case alert.FieldStoppedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field stoppedAt", values[i])
			} else if value.Valid {
				a.StoppedAt = value.Time
			}
		case alert.FieldSourceIp:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field sourceIp", values[i])
			} else if value.Valid {
				a.SourceIp = value.String
			}
		case alert.FieldSourceRange:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field sourceRange", values[i])
			} else if value.Valid {
				a.SourceRange = value.String
			}
		case alert.FieldSourceAsNumber:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field sourceAsNumber", values[i])
			} else if value.Valid {
				a.SourceAsNumber = value.String
			}
		case alert.FieldSourceAsName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field sourceAsName", values[i])
			} else if value.Valid {
				a.SourceAsName = value.String
			}
		case alert.FieldSourceCountry:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field sourceCountry", values[i])
			} else if value.Valid {
				a.SourceCountry = value.String
			}
		case alert.FieldSourceLatitude:
			if value, ok := values[i].(*sql.NullFloat64); !ok {
				return fmt.Errorf("unexpected type %T for field sourceLatitude", values[i])
			} else if value.Valid {
				a.SourceLatitude = float32(value.Float64)
			}
		case alert.FieldSourceLongitude:
			if value, ok := values[i].(*sql.NullFloat64); !ok {
				return fmt.Errorf("unexpected type %T for field sourceLongitude", values[i])
			} else if value.Valid {
				a.SourceLongitude = float32(value.Float64)
			}
		case alert.FieldSourceScope:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field sourceScope", values[i])
			} else if value.Valid {
				a.SourceScope = value.String
			}
		case alert.FieldSourceValue:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field sourceValue", values[i])
			} else if value.Valid {
				a.SourceValue = value.String
			}
		case alert.FieldCapacity:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field capacity", values[i])
			} else if value.Valid {
				a.Capacity = int32(value.Int64)
			}
		case alert.FieldLeakSpeed:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field leakSpeed", values[i])
			} else if value.Valid {
				a.LeakSpeed = value.String
			}
		case alert.FieldScenarioVersion:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field scenarioVersion", values[i])
			} else if value.Valid {
				a.ScenarioVersion = value.String
			}
		case alert.FieldScenarioHash:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field scenarioHash", values[i])
			} else if value.Valid {
				a.ScenarioHash = value.String
			}
		case alert.FieldSimulated:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field simulated", values[i])
			} else if value.Valid {
				a.Simulated = value.Bool
			}
		case alert.FieldUUID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field uuid", values[i])
			} else if value.Valid {
				a.UUID = value.String
			}
		case alert.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for edge-field machine_alerts", value)
			} else if value.Valid {
				a.machine_alerts = new(int)
				*a.machine_alerts = int(value.Int64)
			}
		}
	}
	return nil
}

// QueryOwner queries the "owner" edge of the Alert entity.
func (a *Alert) QueryOwner() *MachineQuery {
	return (&AlertClient{config: a.config}).QueryOwner(a)
}

// QueryDecisions queries the "decisions" edge of the Alert entity.
func (a *Alert) QueryDecisions() *DecisionQuery {
	return (&AlertClient{config: a.config}).QueryDecisions(a)
}

// QueryEvents queries the "events" edge of the Alert entity.
func (a *Alert) QueryEvents() *EventQuery {
	return (&AlertClient{config: a.config}).QueryEvents(a)
}

// QueryMetas queries the "metas" edge of the Alert entity.
func (a *Alert) QueryMetas() *MetaQuery {
	return (&AlertClient{config: a.config}).QueryMetas(a)
}

// Update returns a builder for updating this Alert.
// Note that you need to call Alert.Unwrap() before calling this method if this Alert
// was returned from a transaction, and the transaction was committed or rolled back.
func (a *Alert) Update() *AlertUpdateOne {
	return (&AlertClient{config: a.config}).UpdateOne(a)
}

// Unwrap unwraps the Alert entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (a *Alert) Unwrap() *Alert {
	_tx, ok := a.config.driver.(*txDriver)
	if !ok {
		panic("ent: Alert is not a transactional entity")
	}
	a.config.driver = _tx.drv
	return a
}

// String implements the fmt.Stringer.
func (a *Alert) String() string {
	var builder strings.Builder
	builder.WriteString("Alert(")
	builder.WriteString(fmt.Sprintf("id=%v, ", a.ID))
	if v := a.CreatedAt; v != nil {
		builder.WriteString("created_at=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	builder.WriteString(", ")
	if v := a.UpdatedAt; v != nil {
		builder.WriteString("updated_at=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	builder.WriteString(", ")
	builder.WriteString("scenario=")
	builder.WriteString(a.Scenario)
	builder.WriteString(", ")
	builder.WriteString("bucketId=")
	builder.WriteString(a.BucketId)
	builder.WriteString(", ")
	builder.WriteString("message=")
	builder.WriteString(a.Message)
	builder.WriteString(", ")
	builder.WriteString("eventsCount=")
	builder.WriteString(fmt.Sprintf("%v", a.EventsCount))
	builder.WriteString(", ")
	builder.WriteString("startedAt=")
	builder.WriteString(a.StartedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("stoppedAt=")
	builder.WriteString(a.StoppedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("sourceIp=")
	builder.WriteString(a.SourceIp)
	builder.WriteString(", ")
	builder.WriteString("sourceRange=")
	builder.WriteString(a.SourceRange)
	builder.WriteString(", ")
	builder.WriteString("sourceAsNumber=")
	builder.WriteString(a.SourceAsNumber)
	builder.WriteString(", ")
	builder.WriteString("sourceAsName=")
	builder.WriteString(a.SourceAsName)
	builder.WriteString(", ")
	builder.WriteString("sourceCountry=")
	builder.WriteString(a.SourceCountry)
	builder.WriteString(", ")
	builder.WriteString("sourceLatitude=")
	builder.WriteString(fmt.Sprintf("%v", a.SourceLatitude))
	builder.WriteString(", ")
	builder.WriteString("sourceLongitude=")
	builder.WriteString(fmt.Sprintf("%v", a.SourceLongitude))
	builder.WriteString(", ")
	builder.WriteString("sourceScope=")
	builder.WriteString(a.SourceScope)
	builder.WriteString(", ")
	builder.WriteString("sourceValue=")
	builder.WriteString(a.SourceValue)
	builder.WriteString(", ")
	builder.WriteString("capacity=")
	builder.WriteString(fmt.Sprintf("%v", a.Capacity))
	builder.WriteString(", ")
	builder.WriteString("leakSpeed=")
	builder.WriteString(a.LeakSpeed)
	builder.WriteString(", ")
	builder.WriteString("scenarioVersion=")
	builder.WriteString(a.ScenarioVersion)
	builder.WriteString(", ")
	builder.WriteString("scenarioHash=")
	builder.WriteString(a.ScenarioHash)
	builder.WriteString(", ")
	builder.WriteString("simulated=")
	builder.WriteString(fmt.Sprintf("%v", a.Simulated))
	builder.WriteString(", ")
	builder.WriteString("uuid=")
	builder.WriteString(a.UUID)
	builder.WriteByte(')')
	return builder.String()
}

// Alerts is a parsable slice of Alert.
type Alerts []*Alert

func (a Alerts) config(cfg config) {
	for _i := range a {
		a[_i].config = cfg
	}
}
