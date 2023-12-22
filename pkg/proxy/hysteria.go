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
	ErrorNotHysteriaLink = errors.New("not a correct hysteria link")
)

type Hysteria struct {
	Base
	Ports               string   `yaml:"ports,omitempty" json:"ports,omitempty"`
	AUTHStr             string   `yaml:"auth_str,omitempty" json:"auth_str,omitempty"`
	AUTH                string   `yaml:"auth-str,omitempty" json:"auth-str,omitempty"`
	ALPN                []string `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	SNI                 string   `yaml:"sni,omitempty" json:"sni,omitempty"`
	SkipCertVerify      bool     `yaml:"skip-cert-verify" json:"skip-cert-verify"`
	OBFS                string   `yaml:"obfs,omitempty" json:"obgs,omitempty"`
	FingerPrint         string   `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	CA                  string   `yaml:"ca,omitempty" json:"ca,omitempty"`
	CAStr               string   `yaml:"ca-str,omitempty" json:"ca-str,omitempty"`
	CAStr2              string   `yaml:"ca_str,omitempty" json:"ca_str,omitempty"`
	UP                  string   `yaml:"up" json:"up"`
	DOWN                string   `yaml:"down" json:"down"`
	Protocol            string   `yaml:"protocol" json:"protocol"`
	RecvWindowConn      string   `yaml:"recv_window_conn,omitempty" json:"recv_window_conn,omitempty"`
	RecvWindowConn2     string   `yaml:"recv-window-conn,omitempty" json:"recv-window-conn,omitempty"`
	RecvWindow          string   `yaml:"recv_window,omitempty" json:"recv_window,omitempty"`
	RecvWindow2         string   `yaml:"recv_window2,omitempty" json:"recv_window2,omitempty"`
	DisableMtuDiscovery string   `yaml:"disable_mtu_discovery,omitempty" json:"disable_mtu_discovery,omitempty"`
	FastOpen            string   `yaml:"fast-open,omitempty" json:"fast-open,omitempty"`
}

func (h Hysteria) String() string {
	data, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	return string(data)
}

func (h Hysteria) ToClash() string {
	data, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	return "- " + string(data)
}

func (h Hysteria) ToSurge() string {
	return ""
}

func (h Hysteria) Link() string {
	query := url.Values{}
	if h.Protocol != "" {
		query.Set("protocol", url.QueryEscape(h.Protocol))
	}
	if h.AUTH != "" {
		query.Set("auth", url.QueryEscape(h.AUTH))
	} else if h.AUTHStr != "" {
		query.Set("auth", url.QueryEscape(h.AUTHStr))
	}

	if h.SNI != "" {
		query.Set("peer", url.QueryEscape(h.SNI))
	}

	query.Set("upmbps", url.QueryEscape(h.UP))
	query.Set("downmbps", url.QueryEscape(h.DOWN))
	if h.SkipCertVerify {
		query.Set("insecure", url.QueryEscape("1"))
	} else {
		query.Set("insecure", url.QueryEscape("0"))
	}
	if h.OBFS != "" {
		query.Set("obfs", url.QueryEscape(h.OBFS))
	}
	if len(h.ALPN) != 0 {
		query.Set("alpn", url.QueryEscape(h.ALPN[0]))
	}

	uri := url.URL{
		Scheme:   "hysteria",
		Host:     net.JoinHostPort(h.Server, strconv.Itoa(h.Port)),
		RawQuery: query.Encode(),
		Fragment: h.Name,
	}

	return uri.String()
}

func (h Hysteria) Identifier() string {
	data, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	return string(data)
}

func (h Hysteria) Clone() Proxy {
	return &h
}

func ParseHysteriaLink(link string) (*Hysteria, error) {
	if !strings.HasPrefix(link, "hysteria://") && !strings.HasPrefix(link, "hy://") {
		return nil, ErrorNotHysteriaLink
	}

	uri, err := url.Parse(link)
	if err != nil {
		return nil, ErrorNotHysteriaLink
	}

	server := uri.Hostname()
	port, _ := strconv.Atoi(uri.Port())
	moreInfos := uri.Query()
	peer := moreInfos.Get("peer")
	peer, _ = url.QueryUnescape(peer)
	insecure := moreInfos.Get("insecure")
	insecure, insecureeer := url.QueryUnescape(insecure)
	obfs := moreInfos.Get("obfs")
	obfs, obfserr := url.QueryUnescape(obfs)
	upmbps := moreInfos.Get("upmbps")
	upmbps, _ = url.QueryUnescape(upmbps)
	downmbps := moreInfos.Get("downmbps")
	downmbps, _ = url.QueryUnescape(downmbps)
	auth := moreInfos.Get("auth")
	auth, _ = url.QueryUnescape(auth)
	alpn := moreInfos.Get("alpn")
	alpn, _ = url.QueryUnescape(alpn)
	if port == 0 {
		port = 443
	}

	t := &Hysteria{
		Base: Base{
			Name:   "",
			Server: server,
			Port:   port,
			Type:   "hysteria",
			UDP:    true,
		},
		UP:       upmbps,
		DOWN:     downmbps,
		Protocol: "udp",
		AUTHStr:  auth,
		AUTH:     auth,
	}
	if insecureeer == nil && insecure == "1" {
		t.SkipCertVerify = true
	} else {
		t.SkipCertVerify = false
	}
	if obfserr == nil && obfs == "xplus" {
		t.OBFS = obfs
	}
	if peer != "" {
		t.SNI = peer
	}
	if alpn != "" {
		t.ALPN = []string{alpn}
	}
	return t, nil
}
