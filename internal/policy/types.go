package policy

const (
	ActionPost    = "Post"
	ActionSigkill = "Sigkill"
)

// PolicyFormInput is the data submitted from the frontend form.
type PolicyFormInput struct {
	Name         string            `json:"name"`
	Namespace    string            `json:"namespace,omitempty"`
	PodSelector  map[string]string `json:"podSelector,omitempty"`
	ProcessMode  string            `json:"processMode,omitempty"`  // "whitelist" (NotPostfix) or "blacklist" (Postfix); default whitelist
	Process      []ProcessRule     `json:"process,omitempty"`
	FileMode     string            `json:"fileMode,omitempty"`     // "whitelist" (NotPrefix) or "blacklist" (Prefix); default blacklist
	File         []FileRule        `json:"file,omitempty"`
	Network      []NetworkRule     `json:"network,omitempty"`
	NetworkPorts []string          `json:"networkPorts,omitempty"` // destination ports (DPort), ANDed with address rule
	NetworkMode  string            `json:"networkMode,omitempty"`  // "whitelist" (NotDAddr) or "blacklist" (DAddr)
}

type ProcessRule struct {
	Binaries []string `json:"binaries"`
}

type FileRule struct {
	Paths []string `json:"paths"`
}

type NetworkRule struct {
	Address string `json:"address"` // allowed IP or CIDR, e.g. "127.0.0.1" or "10.0.0.0/8"
}

// TracingPolicy is the Tetragon CRD object used for YAML serialisation.
type TracingPolicy struct {
	APIVersion string            `yaml:"apiVersion" json:"apiVersion"`
	Kind       string            `yaml:"kind"       json:"kind"`
	Metadata   ObjectMeta        `yaml:"metadata"   json:"metadata"`
	Spec       TracingPolicySpec `yaml:"spec"       json:"spec"`
}

type ObjectMeta struct {
	Name      string `yaml:"name"                json:"name"`
	Namespace string `yaml:"namespace,omitempty" json:"namespace,omitempty"`
}

type TracingPolicySpec struct {
	PodSelector *LabelSelector `yaml:"podSelector,omitempty" json:"podSelector,omitempty"`
	KProbes     []KProbeSpec   `yaml:"kprobes,omitempty"     json:"kprobes,omitempty"`
}

type LabelSelector struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty" json:"matchLabels,omitempty"`
}

type KProbeSpec struct {
	Call      string           `yaml:"call"                json:"call"`
	Syscall   bool             `yaml:"syscall"             json:"syscall"`
	Args      []KProbeArg      `yaml:"args,omitempty"      json:"args,omitempty"`
	Selectors []KProbeSelector `yaml:"selectors,omitempty" json:"selectors,omitempty"`
}

type KProbeArg struct {
	Index int    `yaml:"index" json:"index"`
	Type  string `yaml:"type"  json:"type"`
}

type KProbeSelector struct {
	MatchBinaries []BinarySelector `yaml:"matchBinaries,omitempty" json:"matchBinaries,omitempty"`
	MatchArgs     []ArgSelector    `yaml:"matchArgs,omitempty"     json:"matchArgs,omitempty"`
	MatchActions  []ActionSelector `yaml:"matchActions"            json:"matchActions"`
}

type BinarySelector struct {
	Operator string   `yaml:"operator" json:"operator"`
	Values   []string `yaml:"values"   json:"values"`
}

type ArgSelector struct {
	Index    int      `yaml:"index"    json:"index"`
	Operator string   `yaml:"operator" json:"operator"`
	Values   []string `yaml:"values"   json:"values"`
}

type ActionSelector struct {
	Action string `yaml:"action" json:"action"`
}
