package proxy

type Hysteria2 struct {
	Base
	Password       string   `yaml:"password" json:"password"`
	AUTH           string   `yaml:"auth,omitempty" json:"auth,omitempty"`
	ALPN           []string `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	SNI            string   `yaml:"sni,omitempty" json:"sni,omitempty"`
	SkipCertVerify bool     `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`
	UDP            bool     `yaml:"udp,omitempty" json:"udp,omitempty"`
	OBFS           string   `yaml:"obfs,omitempty" json:"obgs,omitempty"`
	OBFSPassword   string   `yaml:"obfs-password,omitempty" json:"obfs-password,omitempty"`
	FingerPrint    string   `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	CA             string   `yaml:"ca,omitempty" json:"ca,omitempty"`
	CAStr          string   `yaml:"ca-str,omitempty" json:"ca-str,omitempty"`
	UP             string   `yaml:"up,omitempty" json:"up,omitempty"`
	DOWN           string   `yaml:"down,omitempty" json:"down,omitempty"`
}
