// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package eval

import (
	"errors"
	"fmt"

	"cel.dev/cel-go/cel"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/proto"
)

// ErrUnsupportedPredicate is returned when an evaluator is asked to run
// against a predicate type it does not have a CEL environment for.
var ErrUnsupportedPredicate = errors.New("eval: unsupported predicate type")

// ErrNonBooleanResult is returned when a CEL expression produces a value
// that is not a boolean.
var ErrNonBooleanResult = errors.New("eval: expression did not return a boolean")

// Evaluator compiles and runs CEL expressions against SLSA predicates.
// One cel.Env is built per supported predicate type so expressions can
// reference predicate fields by their typed proto descriptor.
type Evaluator struct {
	envs map[string]*cel.Env
}

// NewEvaluator builds an Evaluator with one cel.Env for every predicate
// type registered in the package registry.
func NewEvaluator() (*Evaluator, error) {
	e := &Evaluator{envs: map[string]*cel.Env{}}
	for predicateType, factory := range registeredPredicates {
		env, err := buildEnv(factory())
		if err != nil {
			return nil, fmt.Errorf("building CEL env for %s: %w", predicateType, err)
		}
		e.envs[predicateType] = env
	}
	return e, nil
}

// HasEnv reports whether the evaluator has an environment for the given
// predicate type.
func (e *Evaluator) HasEnv(predicateType string) bool {
	_, ok := e.envs[predicateType]
	return ok
}

// Evaluate compiles and runs expression for predicateType, returning the
// boolean result. params is exposed to the expression as the `params`
// variable; predicate as `predicate`; subjects as `subjects`.
func (e *Evaluator) Evaluate(
	predicateType, expression string,
	predicate proto.Message,
	subjects []*intoto.ResourceDescriptor,
	params map[string]any,
) (bool, error) {
	env, ok := e.envs[predicateType]
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrUnsupportedPredicate, predicateType)
	}

	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return false, fmt.Errorf("compiling expression: %w", issues.Err())
	}

	prg, err := env.Program(ast)
	if err != nil {
		return false, fmt.Errorf("building program: %w", err)
	}

	val, _, err := prg.Eval(map[string]any{
		"predicate": predicate,
		"subjects":  subjects,
		"params":    params,
	})
	if err != nil {
		return false, fmt.Errorf("evaluating expression: %w", err)
	}

	b, ok := val.Value().(bool)
	if !ok {
		return false, fmt.Errorf("%w: got %T", ErrNonBooleanResult, val.Value())
	}
	return b, nil
}

// buildEnv constructs a cel.Env that exposes:
//   - predicate: typed as the proto message passed in.
//   - subjects:  list of in-toto ResourceDescriptor.
//   - params:    map<string, dyn> for caller-supplied check parameters.
//   - semverMatches(expected, tag): see VersionedTagMatches.
//   - repoMatches(expected, source): see RepoMatches.
//   - CEL optional types, for fields a producer may omit.
func buildEnv(predicate proto.Message) (*cel.Env, error) {
	predicateName := string(predicate.ProtoReflect().Descriptor().FullName())
	subjectName := string((&intoto.ResourceDescriptor{}).ProtoReflect().Descriptor().FullName())
	return cel.NewEnv(
		// Optional types (a.?b.orValue(x), list[?0], optional.of…) let
		// controls read fields a producer may have omitted without
		// chains of has() guards.
		cel.OptionalTypes(),
		// Allow accessing proto fields by their JSON (camelCase) name so
		// that expressions in YAML controls match the SLSA spec wording.
		cel.JSONFieldNames(true),
		cel.Types(predicate, &intoto.ResourceDescriptor{}),
		cel.Variable("predicate", cel.ObjectType(predicateName)),
		cel.Variable("subjects", cel.ListType(cel.ObjectType(subjectName))),
		cel.Variable("params", cel.MapType(cel.StringType, cel.DynType)),
		semverMatchesFunction(),
		repoMatchesFunction(),
	)
}
