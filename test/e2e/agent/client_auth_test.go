// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build agent || e2e

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ghodss/yaml"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	agentv1alpha1 "github.com/elastic/cloud-on-k8s/v3/pkg/apis/agent/v1alpha1"
	commonv1 "github.com/elastic/cloud-on-k8s/v3/pkg/apis/common/v1"
	"github.com/elastic/cloud-on-k8s/v3/pkg/controller/common/certificates"
	"github.com/elastic/cloud-on-k8s/v3/pkg/controller/common/labels"
	"github.com/elastic/cloud-on-k8s/v3/pkg/controller/common/reconciler"
	"github.com/elastic/cloud-on-k8s/v3/pkg/controller/common/version"
	"github.com/elastic/cloud-on-k8s/v3/test/e2e/test"
	"github.com/elastic/cloud-on-k8s/v3/test/e2e/test/agent"
	"github.com/elastic/cloud-on-k8s/v3/test/e2e/test/elasticsearch"
	"github.com/elastic/cloud-on-k8s/v3/test/e2e/test/kibana"
)

// TestClientAuthTransition_StandaloneAgent tests that when Elasticsearch transitions from client authentication
// required to disabled, a standalone Agent remains healthy and its client certificate secrets are cleaned up.
func TestClientAuthRequiredTransition_StandaloneAgent(t *testing.T) {
	name := "test-sa-mtls-trans"
	namespace := test.Ctx().ManagedNamespace(0)

	esBuilder := elasticsearch.NewBuilder(name).
		WithESMasterDataNodes(3, elasticsearch.DefaultResources).
		WithClientAuthenticationRequired()

	agentBuilder := agent.NewBuilder(name).
		WithElasticsearchRefs(agent.ToOutput(esBuilder.Ref(), "default")).
		WithOpenShiftRoles(test.UseSCCRole).
		WithDefaultESValidation(agent.HasWorkingDataStream(agent.LogsType, "elastic_agent", "default")).
		WithDefaultESValidation(agent.HasWorkingDataStream(agent.LogsType, "elastic_agent.filebeat", "default")).
		WithDefaultESValidation(agent.HasWorkingDataStream(agent.LogsType, "elastic_agent.metricbeat", "default")).
		WithDefaultESValidation(agent.HasWorkingDataStream(agent.MetricsType, "system.cpu", "default"))

	agentBuilder = agent.ApplyYamls(t, agentBuilder, E2EAgentSystemIntegrationConfig, E2EAgentSystemIntegrationPodTemplate).MoreResourcesForIssue4730()

	k := test.NewK8sClientOrFatal()

	// Phase 1: create ES with client auth + standalone Agent, verify healthy and client cert secret exists
	steps := test.StepList{}.
		WithSteps(esBuilder.InitTestSteps(k)).
		WithSteps(agentBuilder.InitTestSteps(k)).
		WithSteps(esBuilder.CreationTestSteps(k)).
		WithSteps(agentBuilder.CreationTestSteps(k)).
		WithSteps(test.CheckTestSteps(esBuilder, k)).
		WithSteps(test.CheckTestSteps(agentBuilder, k)).
		WithSteps(test.StepList{
			{
				Name: "Verify standalone Agent client certificate secret exists",
				Test: test.Eventually(func() error {
					return verifyClientCertSecretCount(k, namespace, esBuilder.Elasticsearch.Name, 1)
				}),
			},
		})

	// Phase 2: transition ES to client auth disabled
	esMutated := esBuilder.DeepCopy()
	esMutated.Elasticsearch.Spec.HTTP.TLS.Client.Authentication = false
	esMutated.MutatedFrom = &esBuilder

	steps = steps.
		WithSteps(esMutated.UpgradeTestSteps(k)).
		WithSteps(test.CheckTestSteps(*esMutated, k)).
		WithSteps(test.CheckTestSteps(agentBuilder, k)).
		WithSteps(test.StepList{
			{
				Name: "Verify standalone Agent client certificate secret is deleted",
				Test: test.Eventually(func() error {
					return verifyClientCertSecretCount(k, namespace, esBuilder.Elasticsearch.Name, 0)
				}),
			},
		}).
		WithSteps(test.CheckTestSteps(agentBuilder, k)).
		WithSteps(agentBuilder.DeletionTestSteps(k)).
		WithSteps(esBuilder.DeletionTestSteps(k))

	steps.RunSequential(t)
}

// TestClientAuthCustomCertificate_StandaloneAgent tests that a standalone Agent works with a user-provided
// client certificate when Elasticsearch requires client authentication.
func TestClientAuthRequiredCustomCertificate_StandaloneAgent(t *testing.T) {
	name := "test-sa-mtls-custom"
	namespace := test.Ctx().ManagedNamespace(0)
	userCertSecretName := name + "-user-client-cert"

	esBuilder := elasticsearch.NewBuilder(name).
		WithESMasterDataNodes(3, elasticsearch.DefaultResources).
		WithClientAuthenticationRequired()

	agentBuilder := agent.NewBuilder(name).
		WithElasticsearchRefs(agent.ToOutputWithClientCert(
			commonv1.ObjectSelector{Name: esBuilder.Elasticsearch.Name, Namespace: esBuilder.Elasticsearch.Namespace},
			userCertSecretName, "default")).
		WithOpenShiftRoles(test.UseSCCRole).
		WithDefaultESValidation(agent.HasWorkingDataStream(agent.LogsType, "elastic_agent", "default")).
		WithDefaultESValidation(agent.HasWorkingDataStream(agent.LogsType, "elastic_agent.filebeat", "default")).
		WithDefaultESValidation(agent.HasWorkingDataStream(agent.LogsType, "elastic_agent.metricbeat", "default")).
		WithDefaultESValidation(agent.HasWorkingDataStream(agent.MetricsType, "system.cpu", "default"))

	agentBuilder = agent.ApplyYamls(t, agentBuilder, E2EAgentSystemIntegrationConfig, E2EAgentSystemIntegrationPodTemplate).MoreResourcesForIssue4730()

	k := test.NewK8sClientOrFatal()

	before := test.StepsFunc(func(k *test.K8sClient) test.StepList {
		return test.StepList{
			{
				Name: "Create user-provided client certificate secret",
				Test: func(t *testing.T) {
					certPEM, keyPEM := generateSelfSignedClientCert(t, name)
					secret := corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      userCertSecretName,
							Namespace: namespace,
						},
						Data: map[string][]byte{
							certificates.CertFileName: certPEM,
							certificates.KeyFileName:  keyPEM,
						},
					}
					require.NoError(t, k.Client.Create(context.Background(), &secret))
				},
			},
		}
	})

	after := test.StepsFunc(func(k *test.K8sClient) test.StepList {
		return test.StepList{
			{
				Name: "Delete user-provided client certificate secret",
				Test: func(t *testing.T) {
					secret := corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      userCertSecretName,
							Namespace: namespace,
						},
					}
					_ = k.Client.Delete(context.Background(), &secret)
				},
			},
		}
	})

	steps := test.StepList{}
	steps = steps.WithSteps(before(k))
	steps = steps.
		WithSteps(esBuilder.InitTestSteps(k)).
		WithSteps(agentBuilder.InitTestSteps(k)).
		WithSteps(esBuilder.CreationTestSteps(k)).
		WithSteps(agentBuilder.CreationTestSteps(k)).
		WithSteps(test.CheckTestSteps(esBuilder, k)).
		WithSteps(test.CheckTestSteps(agentBuilder, k)).
		WithSteps(test.StepList{
			{
				Name: "Verify managed client certificate secret exists with user cert data",
				Test: test.Eventually(func() error {
					secrets, err := listClientCertSecrets(k, namespace, esBuilder.Elasticsearch.Name)
					if err != nil {
						return err
					}
					if len(secrets) != 1 {
						return fmt.Errorf("expected 1 client cert secret, got %d", len(secrets))
					}
					secret := secrets[0]
					if _, ok := secret.Data[certificates.CertFileName]; !ok {
						return fmt.Errorf("managed client cert secret is missing %s", certificates.CertFileName)
					}
					if _, ok := secret.Data[certificates.KeyFileName]; !ok {
						return fmt.Errorf("managed client cert secret is missing %s", certificates.KeyFileName)
					}
					return nil
				}),
			},
		}).
		WithSteps(agentBuilder.DeletionTestSteps(k)).
		WithSteps(esBuilder.DeletionTestSteps(k))
	steps = steps.WithSteps(after(k))

	steps.RunSequential(t)
}

// TestClientAuthTransition_FleetAgent tests that when Elasticsearch transitions from client authentication
// required to disabled, a fleet-managed Agent (and its Fleet Server) remain healthy and transitive client
// certificate secrets are cleaned up.
func TestClientAuthRequiredTransition_FleetAgent(t *testing.T) {
	name := "test-fa-mtls-trans"
	namespace := test.Ctx().ManagedNamespace(0)

	esBuilder := elasticsearch.NewBuilder(name).
		WithESMasterDataNodes(3, elasticsearch.DefaultResources).
		WithClientAuthenticationRequired()

	kbBuilder := kibana.NewBuilder(name).
		WithElasticsearchRef(esBuilder.Ref()).
		WithNodeCount(1)

	fleetServerBuilder := agent.NewBuilder(name + "-fs").
		WithRoles(agent.AgentFleetModeRoleName).
		WithOpenShiftRoles(test.UseSCCRole).
		WithDeployment().
		WithFleetMode().
		WithFleetServer().
		WithElasticsearchRefs(agent.ToOutput(esBuilder.Ref(), "default")).
		WithKibanaRef(kbBuilder.Ref()).
		WithFleetAgentDataStreamsValidation()

	kbBuilder = kbBuilder.WithConfig(fleetConfigWithOutputsForKibana(t, fleetServerBuilder.Agent.Spec.Version, esBuilder.Ref(), fleetServerBuilder.Ref()))

	agentBuilder := agent.NewBuilder(name + "-ea").
		WithRoles(agent.AgentFleetModeRoleName).
		WithOpenShiftRoles(test.UseSCCRole).
		WithFleetMode().
		WithKibanaRef(kbBuilder.Ref()).
		WithFleetServerRef(fleetServerBuilder.Ref())

	fleetServerBuilder = agent.ApplyYamls(t, fleetServerBuilder, "", E2EAgentFleetModePodTemplate)
	agentBuilder = agent.ApplyYamls(t, agentBuilder, "", E2EAgentFleetModePodTemplate)

	k := test.NewK8sClientOrFatal()

	// Phase 1: create ES with client auth + Fleet Server + fleet-managed Agent, verify healthy and client cert secrets exist
	steps := test.StepList{}.
		WithSteps(esBuilder.InitTestSteps(k)).
		WithSteps(kbBuilder.InitTestSteps(k)).
		WithSteps(fleetServerBuilder.InitTestSteps(k)).
		WithSteps(agentBuilder.InitTestSteps(k)).
		WithSteps(esBuilder.CreationTestSteps(k)).
		WithSteps(kbBuilder.CreationTestSteps(k)).
		WithSteps(fleetServerBuilder.CreationTestSteps(k)).
		WithSteps(agentBuilder.CreationTestSteps(k)).
		WithSteps(test.CheckTestSteps(esBuilder, k)).
		WithSteps(test.CheckTestSteps(kbBuilder, k)).
		WithSteps(test.CheckTestSteps(fleetServerBuilder, k)).
		WithSteps(test.CheckTestSteps(agentBuilder, k)).
		WithSteps(test.StepList{
			{
				Name: "Verify Fleet Server client certificate secret exists",
				Test: test.Eventually(func() error {
					return verifyClientCertSecretCount(k, namespace, esBuilder.Elasticsearch.Name, 3)
				}),
			},
		})

	// Phase 2: transition ES to client auth disabled
	esMutated := esBuilder.DeepCopy()
	esMutated.Elasticsearch.Spec.HTTP.TLS.Client.Authentication = false
	esMutated.MutatedFrom = &esBuilder

	steps = steps.
		WithSteps(esMutated.UpgradeTestSteps(k)).
		WithSteps(test.CheckTestSteps(*esMutated, k)).
		WithSteps(test.CheckTestSteps(kbBuilder, k)).
		WithSteps(test.CheckTestSteps(fleetServerBuilder, k)).
		WithSteps(test.CheckTestSteps(agentBuilder, k)).
		WithSteps(test.StepList{
			{
				Name: "Verify all client certificate secrets are deleted",
				Test: test.Eventually(func() error {
					return verifyClientCertSecretCount(k, namespace, esBuilder.Elasticsearch.Name, 0)
				}),
			},
		}).
		WithSteps(test.CheckTestSteps(fleetServerBuilder, k)).
		WithSteps(test.CheckTestSteps(agentBuilder, k)).
		WithSteps(agentBuilder.DeletionTestSteps(k)).
		WithSteps(fleetServerBuilder.DeletionTestSteps(k)).
		WithSteps(kbBuilder.DeletionTestSteps(k)).
		WithSteps(esBuilder.DeletionTestSteps(k))

	steps.RunSequential(t)
}

// TestClientAuthCustomCertificate_FleetAgent tests that a fleet-managed Agent uses the same user-provided
// client certificate as its Fleet Server when Elasticsearch requires client authentication.
func TestClientAuthRequiredCustomCertificate_FleetAgent(t *testing.T) {
	name := "test-fa-mtls-custom"
	namespace := test.Ctx().ManagedNamespace(0)
	userCertSecretName := name + "-user-client-cert"

	esBuilder := elasticsearch.NewBuilder(name).
		WithESMasterDataNodes(3, elasticsearch.DefaultResources).
		WithClientAuthenticationRequired()

	kbBuilder := kibana.NewBuilder(name).
		WithElasticsearchRef(esBuilder.Ref()).
		WithNodeCount(1)

	fleetServerBuilder := agent.NewBuilder(name + "-fs").
		WithRoles(agent.AgentFleetModeRoleName).
		WithOpenShiftRoles(test.UseSCCRole).
		WithDeployment().
		WithFleetMode().
		WithFleetServer().
		WithElasticsearchRefs(agent.ToOutputWithClientCert(
			commonv1.ObjectSelector{Name: esBuilder.Elasticsearch.Name, Namespace: esBuilder.Elasticsearch.Namespace},
			userCertSecretName, "default")).
		WithKibanaRef(kbBuilder.Ref()).
		WithFleetAgentDataStreamsValidation()

	kbBuilder = kbBuilder.WithConfig(fleetConfigWithOutputsForKibana(t, fleetServerBuilder.Agent.Spec.Version, esBuilder.Ref(), fleetServerBuilder.Ref()))

	agentBuilder := agent.NewBuilder(name + "-ea").
		WithRoles(agent.AgentFleetModeRoleName).
		WithOpenShiftRoles(test.UseSCCRole).
		WithFleetMode().
		WithKibanaRef(kbBuilder.Ref()).
		WithFleetServerRef(fleetServerBuilder.Ref())

	fleetServerBuilder = agent.ApplyYamls(t, fleetServerBuilder, "", E2EAgentFleetModePodTemplate)
	agentBuilder = agent.ApplyYamls(t, agentBuilder, "", E2EAgentFleetModePodTemplate)

	k := test.NewK8sClientOrFatal()

	before := test.StepsFunc(func(k *test.K8sClient) test.StepList {
		return test.StepList{
			{
				Name: "Create user-provided client certificate secret",
				Test: func(t *testing.T) {
					certPEM, keyPEM := generateSelfSignedClientCert(t, name)
					secret := corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      userCertSecretName,
							Namespace: namespace,
						},
						Data: map[string][]byte{
							certificates.CertFileName: certPEM,
							certificates.KeyFileName:  keyPEM,
						},
					}
					require.NoError(t, k.Client.Create(context.Background(), &secret))
				},
			},
		}
	})

	after := test.StepsFunc(func(k *test.K8sClient) test.StepList {
		return test.StepList{
			{
				Name: "Delete user-provided client certificate secret",
				Test: func(t *testing.T) {
					secret := corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      userCertSecretName,
							Namespace: namespace,
						},
					}
					_ = k.Client.Delete(context.Background(), &secret)
				},
			},
		}
	})

	steps := test.StepList{}
	steps = steps.WithSteps(before(k))
	steps = steps.
		WithSteps(esBuilder.InitTestSteps(k)).
		WithSteps(kbBuilder.InitTestSteps(k)).
		WithSteps(fleetServerBuilder.InitTestSteps(k)).
		WithSteps(agentBuilder.InitTestSteps(k)).
		WithSteps(esBuilder.CreationTestSteps(k)).
		WithSteps(kbBuilder.CreationTestSteps(k)).
		WithSteps(fleetServerBuilder.CreationTestSteps(k)).
		WithSteps(agentBuilder.CreationTestSteps(k)).
		WithSteps(test.CheckTestSteps(esBuilder, k)).
		WithSteps(test.CheckTestSteps(kbBuilder, k)).
		WithSteps(test.CheckTestSteps(fleetServerBuilder, k)).
		WithSteps(test.CheckTestSteps(agentBuilder, k)).
		WithSteps(test.StepList{
			{
				Name: "Verify Fleet Server managed client certificate secret exists with user cert data",
				Test: test.Eventually(func() error {
					secrets, err := listClientCertSecrets(k, namespace, esBuilder.Elasticsearch.Name)
					if err != nil {
						return err
					}
					if len(secrets) < 1 {
						return fmt.Errorf("expected at least 1 client cert secret, got %d", len(secrets))
					}
					for _, secret := range secrets {
						if _, ok := secret.Data[certificates.CertFileName]; !ok {
							return fmt.Errorf("client cert secret %s is missing %s", secret.Name, certificates.CertFileName)
						}
						if _, ok := secret.Data[certificates.KeyFileName]; !ok {
							return fmt.Errorf("client cert secret %s is missing %s", secret.Name, certificates.KeyFileName)
						}
					}
					return nil
				}),
			},
			{
				Name: "Verify fleet-managed Agent has transitive client cert configured",
				Test: test.Eventually(func() error {
					var ag agentv1alpha1.Agent
					if err := k.Client.Get(context.Background(), types.NamespacedName{
						Namespace: namespace,
						Name:      agentBuilder.Agent.Name,
					}, &ag); err != nil {
						return err
					}
					for _, assoc := range ag.GetAssociations() {
						if assoc.AssociationType() != commonv1.FleetServerAssociationType {
							continue
						}
						conf, err := assoc.AssociationConf()
						if err != nil {
							return err
						}
						if conf == nil || conf.TransitiveESRef == nil || !conf.TransitiveESRef.ClientCertIsConfigured() {
							return fmt.Errorf("fleet-managed Agent should have a transitive ES client cert configured")
						}
						return nil
					}
					return fmt.Errorf("fleet-managed Agent has no Fleet Server association")
				}),
			},
		}).
		WithSteps(agentBuilder.DeletionTestSteps(k)).
		WithSteps(fleetServerBuilder.DeletionTestSteps(k)).
		WithSteps(kbBuilder.DeletionTestSteps(k)).
		WithSteps(esBuilder.DeletionTestSteps(k))
	steps = steps.WithSteps(after(k))

	steps.RunSequential(t)
}

// fleetConfigWithOutputsForKibana builds a Kibana config that uses xpack.fleet.outputs instead of
// xpack.fleet.agents.elasticsearch.hosts. The two cannot coexist. Defining outputs explicitly is
// necessary for mTLS tests so the Kibana controller can inject ssl.certificate and ssl.key into
// the fleet output via injectFleetOutputClientCerts.
func fleetConfigWithOutputsForKibana(t *testing.T, agentVersion string, esRef commonv1.ObjectSelector, fsRef commonv1.ObjectSelector) map[string]interface{} {
	t.Helper()
	cfg := map[string]interface{}{}

	v, err := version.Parse(agentVersion)
	if err != nil {
		t.Fatalf("Unable to parse Agent version: %v", err)
	}
	if v.GTE(version.MustParse("7.16.0")) {
		if err := yaml.Unmarshal([]byte(E2EFleetPolicies), &cfg); err != nil {
			t.Fatalf("Unable to parse Fleet policies: %v", err)
		}
	}

	esURL := fmt.Sprintf("https://%s-es-http.%s.svc:9200", esRef.Name, esRef.Namespace)

	cfg["xpack.fleet.outputs"] = []map[string]interface{}{
		{
			"id":                    "eck-fleet-agent-output-elasticsearch",
			"is_default":            true,
			"is_default_monitoring": true,
			"name":                  "eck-elasticsearch",
			"type":                  "elasticsearch",
			"hosts":                 []string{esURL},
		},
	}

	cfg["xpack.fleet.agents.fleet_server.hosts"] = []string{
		fmt.Sprintf("https://%s-agent-http.%s.svc:8220", fsRef.Name, fsRef.Namespace),
	}

	return cfg
}

// --- Helpers ---

func verifyClientCertSecretCount(k *test.K8sClient, namespace, esName string, expectedCount int) error {
	secrets, err := listClientCertSecrets(k, namespace, esName)
	if err != nil {
		return err
	}
	if len(secrets) != expectedCount {
		return fmt.Errorf("expected %d client cert secrets for ES %s, got %d", expectedCount, esName, len(secrets))
	}
	return nil
}

func listClientCertSecrets(k *test.K8sClient, namespace, esName string) ([]corev1.Secret, error) {
	var secretList corev1.SecretList
	matchLabels := k8sclient.MatchingLabels{
		labels.ClientCertificateLabelName: "true",
	}
	if err := k.Client.List(context.Background(), &secretList, k8sclient.InNamespace(namespace), matchLabels); err != nil {
		return nil, err
	}
	var filtered []corev1.Secret
	for _, s := range secretList.Items {
		if s.Labels[reconciler.SoftOwnerNameLabel] == esName {
			filtered = append(filtered, s)
		}
	}
	return filtered, nil
}

func generateSelfSignedClientCert(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	require.NoError(t, err)

	serial, err := cryptorand.Int(cryptorand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         cn,
			OrganizationalUnit: []string{"eck-e2e-test"},
		},
		NotBefore:          time.Now().Add(-10 * time.Minute),
		NotAfter:           time.Now().Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	certDER, err := x509.CreateCertificate(cryptorand.Reader, &template, &template, privateKey.Public(), privateKey)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}
