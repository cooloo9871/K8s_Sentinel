package webhook

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/cel-go/cel"

	"github.com/cooloo9871/sentinel/internal/admission"
)

// ViolationResult holds a single CEL validation failure.
type ViolationResult struct {
	PolicyName string
	Message    string
	Expression string
}

// Evaluator evaluates admission requests against Sentinel-managed rules.
type Evaluator struct {
	rules *admission.RuleStore
}

func NewEvaluator(rules *admission.RuleStore) *Evaluator {
	return &Evaluator{rules: rules}
}

// Evaluate checks enabled rules against the request and returns violations.
func (e *Evaluator) Evaluate(_ context.Context, req AdmissionRequest) ([]ViolationResult, error) {
	var violations []ViolationResult
	for _, rule := range e.rules.EnabledRules() {
		if !matchesRule(rule, req) {
			continue
		}
		vs, err := evaluateValidations(rule, req)
		if err != nil {
			continue
		}
		violations = append(violations, vs...)
	}
	return violations, nil
}

func matchesRule(rule admission.AdmissionRule, req AdmissionRequest) bool {
	for _, rr := range rule.Spec.MatchConstraints.ResourceRules {
		if matchesResourceRule(rr, req) {
			return true
		}
	}
	return len(rule.Spec.MatchConstraints.ResourceRules) == 0
}

func matchesResourceRule(rr admission.ResourceRule, req AdmissionRequest) bool {
	if !matchSlice(rr.APIGroups, req.Resource.Group) {
		return false
	}
	if !matchSlice(rr.APIVersions, req.Resource.Version) {
		return false
	}
	if !matchSlice(rr.Resources, req.Resource.Resource) {
		return false
	}
	if !matchSlice(rr.Operations, req.Operation) {
		return false
	}
	return true
}

func matchSlice(slice []string, val string) bool {
	if len(slice) == 0 {
		return true
	}
	for _, s := range slice {
		if s == "*" || s == val {
			return true
		}
	}
	return false
}

func evaluateValidations(rule admission.AdmissionRule, req AdmissionRequest) ([]ViolationResult, error) {
	var objMap map[string]interface{}
	if len(req.Object) > 0 {
		_ = json.Unmarshal(req.Object, &objMap)
	}
	if objMap == nil {
		objMap = map[string]interface{}{}
	}
	var oldObjMap map[string]interface{}
	if len(req.OldObject) > 0 {
		_ = json.Unmarshal(req.OldObject, &oldObjMap)
	}
	if oldObjMap == nil {
		oldObjMap = map[string]interface{}{}
	}

	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
		cel.Variable("request", cel.DynType),
	)
	if err != nil {
		return nil, err
	}

	activation := map[string]interface{}{
		"object":    objMap,
		"oldObject": oldObjMap,
		"request": map[string]interface{}{
			"namespace": req.Namespace,
			"operation": req.Operation,
			"name":      req.Name,
		},
	}

	var violations []ViolationResult
	for _, v := range rule.Spec.Validations {
		if v.Expression == "" {
			continue
		}
		passed, err := evalCEL(env, v.Expression, activation)
		if err != nil {
			continue
		}
		if !passed {
			msg := v.Message
			if msg == "" {
				msg = fmt.Sprintf("failed expression: %s", v.Expression)
			}
			violations = append(violations, ViolationResult{
				PolicyName: rule.Name,
				Message:    msg,
				Expression: v.Expression,
			})
		}
	}
	return violations, nil
}

func evalCEL(env *cel.Env, expression string, vars map[string]interface{}) (bool, error) {
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return false, issues.Err()
	}
	prg, err := env.Program(ast)
	if err != nil {
		return false, err
	}
	out, _, err := prg.Eval(vars)
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression did not return bool")
	}
	return b, nil
}
