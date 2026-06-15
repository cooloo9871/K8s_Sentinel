package k8s

import (
	"context"
	"encoding/json"
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

var (
	vapGVR = schema.GroupVersionResource{
		Group:   "admissionregistration.k8s.io",
		Version: "v1",
		Resource: "validatingadmissionpolicies",
	}
	vapBindingGVR = schema.GroupVersionResource{
		Group:   "admissionregistration.k8s.io",
		Version: "v1",
		Resource: "validatingadmissionpolicybindings",
	}
)

// VAPRecord is a ValidatingAdmissionPolicy as returned by the list/get API.
type VAPRecord struct {
	Name             string   `json:"name"`
	FailurePolicy    string   `json:"failurePolicy"`
	ValidationCount  int      `json:"validationCount"`
	CreatedAt        string   `json:"createdAt"`
	RawYAML          string   `json:"rawYaml"`
}

// VAPBindingRecord is a ValidatingAdmissionPolicyBinding as returned by the list/get API.
type VAPBindingRecord struct {
	Name              string   `json:"name"`
	PolicyName        string   `json:"policyName"`
	ValidationActions []string `json:"validationActions"`
	CreatedAt         string   `json:"createdAt"`
	RawYAML           string   `json:"rawYaml"`
}

func (s *Store) ListVAP(ctx context.Context) ([]VAPRecord, error) {
	list, err := s.client.Resource(vapGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list ValidatingAdmissionPolicy: %w", err)
	}
	records := make([]VAPRecord, 0, len(list.Items))
	for _, item := range list.Items {
		r, err := toVAPRecord(item)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, nil
}

func (s *Store) GetVAP(ctx context.Context, name string) (VAPRecord, error) {
	item, err := s.client.Resource(vapGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return VAPRecord{}, fmt.Errorf("get ValidatingAdmissionPolicy %q: %w", name, err)
	}
	return toVAPRecord(*item)
}

func (s *Store) ApplyVAPRaw(ctx context.Context, rawYAML string) error {
	jsonBytes, err := yaml.YAMLToJSON([]byte(rawYAML))
	if err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}
	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal(jsonBytes, &obj.Object); err != nil {
		return fmt.Errorf("unmarshal YAML: %w", err)
	}
	name := obj.GetName()
	_, err = s.client.Resource(vapGVR).Create(ctx, obj, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !k8serrors.IsAlreadyExists(err) {
		return err
	}
	existing, err := s.client.Resource(vapGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	obj.SetResourceVersion(existing.GetResourceVersion())
	_, err = s.client.Resource(vapGVR).Update(ctx, obj, metav1.UpdateOptions{})
	return err
}

func (s *Store) DeleteVAP(ctx context.Context, name string) error {
	err := s.client.Resource(vapGVR).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("delete ValidatingAdmissionPolicy %q: %w", name, err)
	}
	return nil
}

func (s *Store) ListVAPBindings(ctx context.Context) ([]VAPBindingRecord, error) {
	list, err := s.client.Resource(vapBindingGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list ValidatingAdmissionPolicyBinding: %w", err)
	}
	records := make([]VAPBindingRecord, 0, len(list.Items))
	for _, item := range list.Items {
		r, err := toVAPBindingRecord(item)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, nil
}

func (s *Store) GetVAPBinding(ctx context.Context, name string) (VAPBindingRecord, error) {
	item, err := s.client.Resource(vapBindingGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return VAPBindingRecord{}, fmt.Errorf("get ValidatingAdmissionPolicyBinding %q: %w", name, err)
	}
	return toVAPBindingRecord(*item)
}

func (s *Store) ApplyVAPBindingRaw(ctx context.Context, rawYAML string) error {
	jsonBytes, err := yaml.YAMLToJSON([]byte(rawYAML))
	if err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}
	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal(jsonBytes, &obj.Object); err != nil {
		return fmt.Errorf("unmarshal YAML: %w", err)
	}
	name := obj.GetName()
	_, err = s.client.Resource(vapBindingGVR).Create(ctx, obj, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !k8serrors.IsAlreadyExists(err) {
		return err
	}
	existing, err := s.client.Resource(vapBindingGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	obj.SetResourceVersion(existing.GetResourceVersion())
	_, err = s.client.Resource(vapBindingGVR).Update(ctx, obj, metav1.UpdateOptions{})
	return err
}

func (s *Store) DeleteVAPBinding(ctx context.Context, name string) error {
	err := s.client.Resource(vapBindingGVR).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("delete ValidatingAdmissionPolicyBinding %q: %w", name, err)
	}
	return nil
}

func toVAPRecord(item unstructured.Unstructured) (VAPRecord, error) {
	rawJSON, err := json.Marshal(item.Object)
	if err != nil {
		return VAPRecord{}, err
	}
	rawYAML, err := yaml.JSONToYAML(rawJSON)
	if err != nil {
		return VAPRecord{}, err
	}
	failurePolicy, _, _ := unstructured.NestedString(item.Object, "spec", "failurePolicy")
	validations, _, _ := unstructured.NestedSlice(item.Object, "spec", "validations")
	createdAt := ""
	if ts := item.GetCreationTimestamp(); !ts.IsZero() {
		createdAt = ts.UTC().Format("2006-01-02T15:04:05Z")
	}
	return VAPRecord{
		Name:            item.GetName(),
		FailurePolicy:   failurePolicy,
		ValidationCount: len(validations),
		CreatedAt:       createdAt,
		RawYAML:         string(rawYAML),
	}, nil
}

func toVAPBindingRecord(item unstructured.Unstructured) (VAPBindingRecord, error) {
	rawJSON, err := json.Marshal(item.Object)
	if err != nil {
		return VAPBindingRecord{}, err
	}
	rawYAML, err := yaml.JSONToYAML(rawJSON)
	if err != nil {
		return VAPBindingRecord{}, err
	}
	policyName, _, _ := unstructured.NestedString(item.Object, "spec", "policyName")
	actions, _, _ := unstructured.NestedStringSlice(item.Object, "spec", "validationActions")
	createdAt := ""
	if ts := item.GetCreationTimestamp(); !ts.IsZero() {
		createdAt = ts.UTC().Format("2006-01-02T15:04:05Z")
	}
	return VAPBindingRecord{
		Name:              item.GetName(),
		PolicyName:        policyName,
		ValidationActions: actions,
		CreatedAt:         createdAt,
		RawYAML:           string(rawYAML),
	}, nil
}
