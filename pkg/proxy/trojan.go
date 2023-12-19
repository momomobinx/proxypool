package proxy

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrorNotTrojanink = errors.New("not a correct trojan link")
)

// TODO unknown field
// Link: host, path
// Trojan: Network GrpcOpts

type Trojan struct {
	Base
	Password       string           `yaml:"password" json:"password"`
	ALPN           []string         `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	SNI            string           `yaml:"sni,omitempty" json:"sni,omitempty"`
	SkipCertVerify bool             `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`
	WSOpts         *TrojanWSOptions `yaml:"ws-opts,omitempty" json:"ws-opts,omitempty"`
	FingerPrint    string           `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	// Network        string      `yaml:"network,omitempty" json:"network,omitempty"`
	GrpcOpts *GrpcOptions `yaml:"grpc-opts,omitempty" json:"grpc-opts,omitempty"`
	Flow     string       `yaml:"flow,omitempty" json:"flow,omitempty"`
	FlowShow bool         `yaml:"flow-show,omitempty" json:"flow-show,omitempty"`
}
type TrojanWSOptions struct {
	Path             string            `yaml:"path,omitempty" json:"path,omitempty"`
	Headers          map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	V2rayHttpUpgrade bool              `yaml:"v2ray-http-upgrade,omitempty" json:"v2ray-http-upgrade,omitempty"`
}
type GrpcOptions struct {
	GrpcServiceName string `yaml:"grpc-service-name,omitempty" json:"grpc-service-name,omitempty"`
}

/**
  - name: "trojan"
    type: trojan
    server: server
    port: 443
    password: yourpsk
    # udp: true
    # sni: example.com # aka server name
    # alpn:
    #   - h2
    #   - http/1.1
    # skip-cert-verify: true
*/

func (t Trojan) Identifier() string {
	return net.JoinHostPort(t.Server, strconv.Itoa(t.Port)) + t.Password
}

func (t Trojan) String() string {
	data, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	return string(data)
}

func (t Trojan) ToClash() string {
	data, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	return "- " + string(data)
}

func (t Trojan) ToSurge() string {
	return ""
}

func (t Trojan) Clone() Proxy {
	return &t
}

// https://p4gefau1t.github.io/trojan-go/developer/url/
func (t Trojan) Link() (link string) {
	query := url.Values{}
	if t.SNI != "" {
		query.Set("sni", url.QueryEscape(t.SNI))
	}

	if t.WSOpts != nil && t.WSOpts.Path != "" {
		query.Set("path", url.QueryEscape(t.WSOpts.Path))
	}

	if t.GrpcOpts != nil && t.GrpcOpts.GrpcServiceName != "" {
		query.Set("serviceName", url.QueryEscape(t.GrpcOpts.GrpcServiceName))
	}

	if !t.SkipCertVerify {
		query.Set("security", url.QueryEscape("tls"))
	}

	uri := url.URL{
		Scheme:   "trojan",
		User:     url.User(url.QueryEscape(t.Password)),
		Host:     net.JoinHostPort(t.Server, strconv.Itoa(t.Port)),
		RawQuery: query.Encode(),
		Fragment: t.Name,
	}

	return uri.String()
}

func ParseTrojanLink(link string) (*Trojan, error) {
	if !strings.HasPrefix(link, "trojan://") && !strings.HasPrefix(link, "trojan-go://") {
		return nil, ErrorNotTrojanink
	}

	/**
	trojan-go://
	    $(trojan-password)
	    @
	    trojan-host
	    :
	    port
	/?
	    sni=$(tls-sni.com)&
	    type=$(original|ws|h2|h2+ws)&
	        host=$(websocket-host.com)&
	        path=$(/websocket/path)&
	    encryption=$(ss;aes-256-gcm;ss-password)&
	    plugin=$(...)
	#$(descriptive-text)
	*/

	uri, err := url.Parse(link)
	if err != nil {
		return nil, ErrorNotSSLink
	}

	password := uri.User.Username()
	password, _ = url.QueryUnescape(password)

	server := uri.Hostname()
	port, _ := strconv.Atoi(uri.Port())

	moreInfos := uri.Query()
	sni := moreInfos.Get("sni")
	sni, _ = url.QueryUnescape(sni)
	transformType := moreInfos.Get("type")
	transformType, _ = url.QueryUnescape(transformType)
	host := moreInfos.Get("host")
	host, hostErr := url.QueryUnescape(host)
	path := moreInfos.Get("path")
	path, patherr := url.QueryUnescape(path)
	serviceName := moreInfos.Get("serviceName")
	serviceName, serviceNameerr := url.QueryUnescape(serviceName)
	flow := moreInfos.Get("flow")
	flow, flowerr := url.QueryUnescape(flow)
	flowShow := moreInfos.Get("flowshow")
	flowShow, flowshowerr := url.QueryUnescape(flowShow)
	security := moreInfos.Get("security")
	security, securityerr := url.QueryUnescape(security)
	allowInsecure := moreInfos.Get("allowInsecure")
	allowInsecure, allowInsecureerr := url.QueryUnescape(allowInsecure)
	fingerprint := moreInfos.Get("fp")
	fingerprint, fingerprinterr := url.QueryUnescape(fingerprint)
	alpn := make([]string, 0)
	if transformType == "h2" {
		alpn = append(alpn, "h2")
	}

	if port == 0 {
		port = 443
	}
	//if !ValidPassword(password) {
	//	return nil, errors.New("Password Error")
	//}
	t := &Trojan{
		Base: Base{
			Name:   "",
			Server: server,
			Port:   port,
			Type:   "trojan",
			UDP:    true,
		},
		Password: password,
		ALPN:     alpn,
		SNI:      sni,
	}
	if securityerr == nil && security == "tls" {
		t.SkipCertVerify = false
	} else {
		t.SkipCertVerify = true
	}

	if fingerprinterr == nil && fingerprint != "" {
		t.FingerPrint = fingerprint
	}

	if allowInsecureerr == nil && allowInsecure == "true" {
		t.SkipCertVerify = true
	}
	if flowerr == nil && flow != "" {
		t.Flow = flow
		if flowshowerr != nil && flowShow != "" {
			t.FlowShow = true
		}
	}
	if serviceNameerr == nil && serviceName != "" {
		t.GrpcOpts = &GrpcOptions{
			GrpcServiceName: serviceName,
		}
	}
	if patherr == nil && path != "" {
		if hostErr == nil && host != "" {
			wsHeaders := make(map[string]string)
			wsHeaders["Host"] = host
			t.WSOpts = &TrojanWSOptions{
				Path:    path,
				Headers: wsHeaders,
			}
		} else {
			wsHeaders := make(map[string]string)
			wsHeaders["Host"] = server
			t.WSOpts = &TrojanWSOptions{
				Path:    path,
				Headers: wsHeaders,
			}
		}
	}
	return t, nil
}

var (
	trojanPlainRe = regexp.MustCompile("trojan(-go)?://([A-Za-z0-9+/_&?=@:%.-])+")
)

func GrepTrojanLinkFromString(text string) []string {
	results := make([]string, 0)
	if !strings.Contains(text, "trojan://") {
		return results
	}
	texts := strings.Split(text, "trojan://")
	for _, text := range texts {
		results = append(results, trojanPlainRe.FindAllString("trojan://"+text, -1)...)
	}
	return results
}
