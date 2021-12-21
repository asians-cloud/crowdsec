// Copyright 2019-present Facebook Inc. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package entsql

import "entgo.io/ent/schema"

// Annotation is a builtin schema annotation for attaching
// SQL metadata to schema objects for both codegen and runtime.
type Annotation struct {
	// The Table option allows overriding the default table
	// name that is generated by ent. For example:
	//
	//	entsql.Annotation{
	//		Table: "Users",
	//	}
	//
	Table string `json:"table,omitempty"`

	// Charset defines the character-set of the table. For example:
	//
	//	entsql.Annotation{
	//		Charset: "utf8mb4",
	//	}
	//
	Charset string `json:"charset,omitempty"`

	// Collation defines the collation of the table (a set of rules for comparing
	// characters in a character set). For example:
	//
	//	entsql.Annotation{
	//		Collation: "utf8mb4_bin",
	//	}
	//
	Collation string `json:"collation,omitempty"`

	// Default specifies the default value of a column. Note that using this option
	// will override the default behavior of the code-generation. For example:
	//
	//	entsql.Annotation{
	//		Default: "CURRENT_TIMESTAMP",
	//	}
	//
	//	entsql.Annotation{
	//		Default: "uuid_generate_v4()",
	//	}
	//
	Default string `json:"default,omitempty"`

	// Options defines the additional table options. For example:
	//
	//	entsql.Annotation{
	//		Options: "ENGINE = INNODB",
	//	}
	//
	Options string `json:"options,omitempty"`

	// Size defines the column size in the generated schema. For example:
	//
	//	entsql.Annotation{
	//		Size: 128,
	//	}
	//
	Size int64 `json:"size,omitempty"`

	// Incremental defines the autoincremental behavior of a column. For example:
	//
	//  incrementalEnabled := true
	//  entsql.Annotation{
	//      Incremental: &incrementalEnabled,
	//  }
	//
	// By default, this value is nil defaulting to whatever best fits each scenario.
	//
	Incremental *bool `json:"incremental,omitempty"`

	// OnDelete specifies a custom referential action for DELETE operations on parent
	// table that has matching rows in the child table.
	//
	// For example, in order to delete rows from the parent table and automatically delete
	// their matching rows in the child table, pass the following annotation:
	//
	//	entsql.Annotation{
	//		OnDelete: entsql.Cascade,
	//	}
	//
	OnDelete ReferenceOption `json:"on_delete,omitempty"`

	// Check allows injecting custom "DDL" for setting an unnamed "CHECK" clause in "CREATE TABLE".
	//
	//	entsql.Annotation{
	//		Check: "age < 10",
	//	}
	//
	Check string `json:"check,omitempty"`

	// Checks allows injecting custom "DDL" for setting named "CHECK" clauses in "CREATE TABLE".
	//
	//	entsql.Annotation{
	//		Checks: map[string]string{
	//			"valid_discount": "price > discount_price",
	//		},
	//	}
	//
	Checks map[string]string `json:"checks,omitempty"`
}

// Name describes the annotation name.
func (Annotation) Name() string {
	return "EntSQL"
}

// Merge implements the schema.Merger interface.
func (a Annotation) Merge(other schema.Annotation) schema.Annotation {
	var ant Annotation
	switch other := other.(type) {
	case Annotation:
		ant = other
	case *Annotation:
		if other != nil {
			ant = *other
		}
	default:
		return a
	}
	if t := ant.Table; t != "" {
		a.Table = t
	}
	if c := ant.Charset; c != "" {
		a.Charset = c
	}
	if c := ant.Collation; c != "" {
		a.Collation = c
	}
	if o := ant.Options; o != "" {
		a.Options = o
	}
	if s := ant.Size; s != 0 {
		a.Size = s
	}
	if s := ant.Incremental; s != nil {
		a.Incremental = s
	}
	if s := ant.OnDelete; s != "" {
		a.OnDelete = s
	}
	if c := ant.Check; c != "" {
		a.Check = c
	}
	if checks := ant.Checks; len(checks) > 0 {
		if a.Checks == nil {
			a.Checks = make(map[string]string)
		}
		for name, check := range checks {
			a.Checks[name] = check
		}
	}
	return a
}

var (
	_ schema.Annotation = (*Annotation)(nil)
	_ schema.Merger     = (*Annotation)(nil)
)

// ReferenceOption for constraint actions.
type ReferenceOption string

// Reference options (actions) specified by ON UPDATE and ON DELETE
// subclauses of the FOREIGN KEY clause.
const (
	NoAction   ReferenceOption = "NO ACTION"
	Restrict   ReferenceOption = "RESTRICT"
	Cascade    ReferenceOption = "CASCADE"
	SetNull    ReferenceOption = "SET NULL"
	SetDefault ReferenceOption = "SET DEFAULT"
)

// IndexAnnotation is a builtin schema annotation for attaching
// SQL metadata to schema indexes for both codegen and runtime.
type IndexAnnotation struct {
	// Prefix defines a column prefix for a single string column index.
	// In MySQL, the following annotation maps to:
	//
	//	index.Fields("column").
	//		Annotation(entsql.Prefix(100))
	//
	//	CREATE INDEX `table_column` ON `table`(`column`(100))
	//
	Prefix uint

	// PrefixColumns defines column prefixes for a multi column index.
	// In MySQL, the following annotation maps to:
	//
	//	index.Fields("c1", "c2", "c3").
	//		Annotation(
	//			entsql.PrefixColumn("c1", 100),
	//			entsql.PrefixColumn("c2", 200),
	//		)
	//
	//	CREATE INDEX `table_c1_c2_c3` ON `table`(`c1`(100), `c2`(200), `c3`)
	//
	PrefixColumns map[string]uint
}

// Prefix returns a new index annotation with a single string column index.
// In MySQL, the following annotation maps to:
//
//	index.Fields("column").
//		Annotation(entsql.Prefix(100))
//
//	CREATE INDEX `table_column` ON `table`(`column`(100))
//
func Prefix(prefix uint) *IndexAnnotation {
	return &IndexAnnotation{
		Prefix: prefix,
	}
}

// PrefixColumns returns a new index annotation with column prefix for
// multi-column indexes. In MySQL, the following annotation maps to:
//
//	index.Fields("c1", "c2", "c3").
//		Annotation(
//			entsql.PrefixColumn("c1", 100),
//			entsql.PrefixColumn("c2", 200),
//		)
//
//	CREATE INDEX `table_c1_c2_c3` ON `table`(`c1`(100), `c2`(200), `c3`)
//
func PrefixColumn(name string, prefix uint) *IndexAnnotation {
	return &IndexAnnotation{
		PrefixColumns: map[string]uint{
			name: prefix,
		},
	}
}

// Name describes the annotation name.
func (IndexAnnotation) Name() string {
	return "EntSQLIndexes"
}

// Merge implements the schema.Merger interface.
func (a IndexAnnotation) Merge(other schema.Annotation) schema.Annotation {
	var ant IndexAnnotation
	switch other := other.(type) {
	case IndexAnnotation:
		ant = other
	case *IndexAnnotation:
		if other != nil {
			ant = *other
		}
	default:
		return a
	}
	if ant.Prefix != 0 {
		a.Prefix = ant.Prefix
	}
	if ant.PrefixColumns != nil {
		if a.PrefixColumns == nil {
			a.PrefixColumns = make(map[string]uint)
		}
		for column, prefix := range ant.PrefixColumns {
			a.PrefixColumns[column] = prefix
		}
	}
	return a
}

var (
	_ schema.Annotation = (*IndexAnnotation)(nil)
	_ schema.Merger     = (*IndexAnnotation)(nil)
)
