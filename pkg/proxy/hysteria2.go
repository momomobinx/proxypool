package proxy

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var (
	ErrorNotHysteria2Link = errors.New("not a correct hysteria2 link")
)

type Hysteria2 struct {
	Base
	Password       string   `yaml:"password" json:"password"`
	AUTH           string   `yaml:"auth,omitempty" json:"auth,omitempty"`
	ALPN           []string `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	SNI            string   `yaml:"sni,omitempty" json:"sni,omitempty"`
	SkipCertVerify bool     `yaml:"skip-cert-verify" json:"skip-cert-verify"`
	OBFS           string   `yaml:"obfs,omitempty" json:"obgs,omitempty"`
	OBFSPassword   string   `yaml:"obfs-password,omitempty" json:"obfs-password,omitempty"`
	FingerPrint    string   `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	CA             string   `yaml:"ca,omitempty" json:"ca,omitempty"`
	CAStr          string   `yaml:"ca-str,omitempty" json:"ca-str,omitempty"`
	UP             string   `yaml:"up,omitempty" json:"up,omitempty"`
	DOWN           string   `yaml:"down,omitempty" json:"down,omitempty"`
}

func (h Hysteria2) String() string {
	data, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	return string(data)
}

func (h Hysteria2) ToClash() string {
	data, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	return "- " + string(data)
}

func (h Hysteria2) ToSurge() string {
	return ""
}

func (h Hysteria2) Link() string {
	query := url.Values{}
	if h.SNI != "" {
		query.Set("sni", url.QueryEscape(h.SNI))
	}
	if h.SkipCertVerify {
		query.Set("insecure", url.QueryEscape("1"))
	} else {
		query.Set("insecure", url.QueryEscape("0"))
	}
	if h.OBFS != "" {
		query.Set("obfs", url.QueryEscape(h.OBFS))
		if h.OBFSPassword != "" {
			query.Set("obfs-password", url.QueryEscape(h.OBFSPassword))
		}
	}

	uri := url.URL{
		Scheme:   "hysteria2",
		User:     url.User(url.QueryEscape(h.Password)),
		Host:     net.JoinHostPort(h.Server, strconv.Itoa(h.Port)),
		RawQuery: query.Encode(),
		Fragment: h.Name,
	}

	return uri.String()
}

func (h Hysteria2) Identifier() string {
	data, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	return string(data)
}

func (h Hysteria2) Clone() Proxy {
	return &h
}

func ParseHysteria2Link(link string) (*Hysteria2, error) {
	if !strings.HasPrefix(link, "hysteria2://") && !strings.HasPrefix(link, "hy2://") {
		return nil, ErrorNotHysteria2Link
	}

	uri, err := url.Parse(link)
	if err != nil {
		return nil, ErrorNotHysteria2Link
	}

	password := uri.User.Username()
	password, _ = url.QueryUnescape(password)
	server := uri.Hostname()
	port, _ := strconv.Atoi(uri.Port())

	moreInfos := uri.Query()
	sni := moreInfos.Get("sni")
	sni, _ = url.QueryUnescape(sni)
	insecure := moreInfos.Get("insecure")
	insecure, insecureeer := url.QueryUnescape(insecure)
	obfs := moreInfos.Get("obfs")
	obfs, obfserr := url.QueryUnescape(obfs)
	obfsPassword := moreInfos.Get("obfs-password")
	obfsPassword, obfsPassworderr := url.QueryUnescape(obfsPassword)
	if port == 0 {
		port = 443
	}
	//if !ValidPassword(password) {
	//	return nil, errors.New("Password Error")
	//}
	t := &Hysteria2{
		Base: Base{
			Name:   "",
			Server: server,
			Port:   port,
			Type:   "hysteria2",
			UDP:    true,
		},
		Password: password,
		SNI:      sni,
	}
	if insecureeer == nil && insecure == "1" {
		t.SkipCertVerify = true
	} else {
		t.SkipCertVerify = false
	}
	if obfserr == nil && obfs == "salamander" {
		t.OBFS = obfs
		if obfsPassworderr == nil && obfsPassword != "" {
			t.OBFSPassword = obfsPassword
		}
	}
	return t, nil
}
