package webhook

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/cel-go/cel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"

	"github.com/cooloo9871/sentinel/internal/k8s"
)

// ViolationResult holds a single CEL validation failure.
type ViolationResult struct {
	PolicyName  string
	BindingName string
	Message     string
	Expression  string
}

// Evaluator fetches VAP policies and evaluates them against admission requests.
type Evaluator struct {
	dynClient dynamic.Interface
}

func NewEvaluator(dynClient dynamic.Interface) *Evaluator {
	return &Evaluator{dynClient: dynClient}
}

// Evaluate checks all VAP policies that match the request and returns violations.
func (e *Evaluator) Evaluate(ctx context.Context, req AdmissionRequest) ([]ViolationResult, error) {
	// Fetch all VAP policies
	policies, err := e.dynClient.Resource(k8s.ExportVAPGVR()).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list VAP: %w", err)
	}
	// Fetch all VAP bindings
	bindings, err := e.dynClient.Resource(k8s.ExportVAPBindingGVR()).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list VAPBinding: %w", err)
	}

	// Build policy name → binding name map
	policyBindings := map[string]string{}
	for _, b := range bindings.Items {
		policyName, _, _ := unstructured.NestedString(b.Object, "spec", "policyName")
		if policyName != "" {
			policyBindings[policyName] = b.GetName()
		}
	}

	var violations []ViolationResult
	for _, policy := range policies.Items {
		if !matchesPolicy(policy, req) {
			continue
		}
		vs, err := evaluateValidations(policy, req)
		if err != nil {
			continue
		}
		for _, v := range vs {
			v.PolicyName = policy.GetName()
			v.BindingName = policyBindings[policy.GetName()]
			violations = append(violations, v)
		}
	}
	return violations, nil
}

func matchesPolicy(policy unstructured.Unstructured, req AdmissionRequest) bool {
	rules, _, _ := unstructured.NestedSlice(policy.Object, "spec", "matchConstraints", "resourceRules")
	if len(rules) == 0 {
		return true // no constraints = match all
	}
	for _, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		if matchesRule(rule, req) {
			return true
		}
	}
	return false
}

func matchesRule(rule map[string]interface{}, req AdmissionRequest) bool {
	groups, _, _ := unstructured.NestedStringSlice(rule, "apiGroups")
	versions, _, _ := unstructured.NestedStringSlice(rule, "apiVersions")
	resources, _, _ := unstructured.NestedStringSlice(rule, "resources")
	operations, _, _ := unstructured.NestedStringSlice(rule, "operations")

	if !matchSlice(groups, req.Resource.Group) {
		return false
	}
	if !matchSlice(versions, req.Resource.Version) {
		return false
	}
	if !matchSlice(resources, req.Resource.Resource) {
		return false
	}
	if !matchSlice(operations, req.Operation) {
		return false
	}
	return true
}

func matchSlice(slice []string, val string) bool {
	for _, s := range slice {
		if s == "*" || s == val {
			return true
		}
	}
	return len(slice) == 0 // empty = match all
}

func evaluateValidations(policy unstructured.Unstructured, req AdmissionRequest) ([]ViolationResult, error) {
	validations, _, _ := unstructured.NestedSlice(policy.Object, "spec", "validations")

	// Parse object
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
	for _, v := range validations {
		val, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		expr, _ := val["expression"].(string)
		msg, _ := val["message"].(string)
		if expr == "" {
			continue
		}
		passed, err := evalCEL(env, expr, activation)
		if err != nil {
			continue
		}
		if !passed {
			if msg == "" {
				msg = fmt.Sprintf("failed expression: %s", expr)
			}
			violations = append(violations, ViolationResult{
				Message:    msg,
				Expression: expr,
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
