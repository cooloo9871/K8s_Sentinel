package webhook

import (
	"context"
	"log"

	admregv1 "k8s.io/api/admissionregistration/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const webhookName = "sentinel.sentinel-system.svc"
const webhookConfigName = "sentinel-admission"

// Register creates or updates the ValidatingWebhookConfiguration.
func Register(ctx context.Context, typed kubernetes.Interface, caBundle []byte, svcNamespace, svcName string) error {
	path := "/api/admission"
	port := int32(443)
	sideEffects := admregv1.SideEffectClassNone
	failPolicy := admregv1.Ignore
	scope := admregv1.AllScopes

	webhookCfg := &admregv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: webhookConfigName},
		Webhooks: []admregv1.ValidatingWebhook{
			{
				Name: webhookName,
				ClientConfig: admregv1.WebhookClientConfig{
					Service: &admregv1.ServiceReference{
						Namespace: svcNamespace,
						Name:      svcName,
						Path:      &path,
						Port:      &port,
					},
					CABundle: caBundle,
				},
				Rules: []admregv1.RuleWithOperations{
					{
						Operations: []admregv1.OperationType{
							admregv1.Create,
							admregv1.Update,
						},
						Rule: admregv1.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"*"},
							Resources:   []string{"*"},
							Scope:       &scope,
						},
					},
				},
				// Exclude system namespaces to avoid intercepting K8s internals
				NamespaceSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "kubernetes.io/metadata.name",
							Operator: metav1.LabelSelectorOpNotIn,
							Values:   []string{"kube-system", "kube-public", "kube-node-lease", "sentinel-system"},
						},
					},
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             &sideEffects,
				FailurePolicy:           &failPolicy,
			},
		},
	}

	existing, err := typed.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, webhookConfigName, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		_, err = typed.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(ctx, webhookCfg, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		log.Printf("admission-webhook: registered %q", webhookConfigName)
		return nil
	}
	if err != nil {
		return err
	}
	webhookCfg.ResourceVersion = existing.ResourceVersion
	_, err = typed.AdmissionregistrationV1().ValidatingWebhookConfigurations().Update(ctx, webhookCfg, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	log.Printf("admission-webhook: updated %q", webhookConfigName)
	return nil
}

// Deregister removes the ValidatingWebhookConfiguration.
func Deregister(ctx context.Context, typed kubernetes.Interface) {
	typed.AdmissionregistrationV1().ValidatingWebhookConfigurations().Delete(ctx, webhookConfigName, metav1.DeleteOptions{})
}
