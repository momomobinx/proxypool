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
	ErrorNotTuicLink = errors.New("not a correct tuic link")
)

// TODO unknown field
// Link: host, path
// Tuic: Network GrpcOpts

type Tuic struct {
	Base
	Password             string   `yaml:"password,omitempty" json:"password,omitempty"`
	UUID                 string   `yaml:"uuid,omitempty" json:"uuid,omitempty"`
	Token                string   `yaml:"token,omitempty" json:"token,omitempty"`
	ALPN                 []string `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	SNI                  string   `yaml:"sni,omitempty" json:"sni,omitempty"`
	SkipCertVerify       bool     `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`
	DisableSni           bool     `yaml:"disable-sni,omitempty" json:"disable-sni,omitempty"`
	ReduceRtt            bool     `yaml:"reduce-rtt,omitempty" json:"reduce-rtt,omitempty"`
	UdpRelayMode         string   `yaml:"udp-relay-mode,omitempty" json:"udp-relay-mode,omitempty"`
	CongestionController string   `yaml:"congestion-controller,omitempty" json:"congestion-controller,omitempty"`
}

/**
  - name: "Tuic"
    type: Tuic
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

func (t Tuic) Identifier() string {
	return net.JoinHostPort(t.Server, strconv.Itoa(t.Port)) + t.Password
}

func (t Tuic) String() string {
	data, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	return string(data)
}

func (t Tuic) ToClash() string {
	data, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	return "- " + string(data)
}

func (t Tuic) ToSurge() string {
	return ""
}

func (t Tuic) Clone() Proxy {
	return &t
}

// https://p4gefau1t.github.io/Tuic-go/developer/url/
func (t Tuic) Link() (link string) {
	query := url.Values{}
	if t.SNI != "" {
		query.Set("sni", url.QueryEscape(t.SNI))
	}

	if t.SkipCertVerify {
		query.Set("insecure", url.QueryEscape("1"))
	} else {
		query.Set("insecure", url.QueryEscape("0"))
	}

	if t.CongestionController != "" {
		query.Set("congestion_control", url.QueryEscape(t.CongestionController))
	}
	if t.UdpRelayMode != "" {
		query.Set("udp_relay_mode", url.QueryEscape(t.UdpRelayMode))

	}
	if len(t.ALPN) > 0 {
		query.Set("alpn", url.QueryEscape(t.ALPN[0]))
	}

	uri := url.URL{
		Scheme:   "tuic",
		User:     url.UserPassword(url.QueryEscape(t.UUID), url.QueryEscape(t.Password)),
		Host:     net.JoinHostPort(t.Server, strconv.Itoa(t.Port)),
		RawQuery: query.Encode(),
		Fragment: t.Name,
	}

	return uri.String()
}

func ParseTuicLink(link string) (*Tuic, error) {
	if !strings.HasPrefix(link, "tuic://") {
		return nil, ErrorNotTuicLink
	}

	/**
	Tuic-go://
	    $(Tuic-password)
	    @
	    Tuic-host
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

	uuid := uri.User.Username()
	uuid, _ = url.QueryUnescape(uuid)
	password, _ := uri.User.Password()
	server := uri.Hostname()
	port, _ := strconv.Atoi(uri.Port())

	moreInfos := uri.Query()
	sni := moreInfos.Get("sni")
	sni, _ = url.QueryUnescape(sni)
	insecure := moreInfos.Get("insecure")
	insecure, insecureeer := url.QueryUnescape(insecure)
	transformType := moreInfos.Get("alpn")
	transformType, transformTypeErr := url.QueryUnescape(transformType)
	udprelaymode := moreInfos.Get("udp_relay_mode")
	udprelaymode, udprelaymodeErr := url.QueryUnescape(udprelaymode)
	congestionController := moreInfos.Get("congestion_control")
	congestionController, congestionControllerErr := url.QueryUnescape(congestionController)

	if port == 0 {
		port = 443
	}
	//if !ValidPassword(password) {
	//	return nil, errors.New("Password Error")
	//}
	t := &Tuic{
		Base: Base{
			Name:   "",
			Server: server,
			Port:   port,
			Type:   "tuic",
			UDP:    true,
		},
		Password: password,
		SNI:      sni,
	}

	if insecureeer == nil && insecure == "1" {
		t.SkipCertVerify = false
	} else {
		t.SkipCertVerify = true
	}
	alpn := make([]string, 0)
	if transformTypeErr == nil && transformType != "" {
		alpn = append(alpn, transformType)
		t.ALPN = alpn
		t.SkipCertVerify = false
	}
	if udprelaymodeErr == nil && udprelaymode != "" {
		t.UdpRelayMode = udprelaymode
	}

	if congestionControllerErr == nil && congestionController != "" {
		t.CongestionController = congestionController
	}

	if uuid != "" {
		t.UUID = uuid
	}
	return t, nil
}

var (
	TuicPlainRe = regexp.MustCompile("tuic://([A-Za-z0-9+/_&?=@:%.-])+")
)

func GrepTuicLinkFromString(text string) []string {
	results := make([]string, 0)
	if !strings.Contains(text, "tuic://") {
		return results
	}
	texts := strings.Split(text, "tuic://")
	for _, text := range texts {
		results = append(results, TuicPlainRe.FindAllString("tuic://"+text, -1)...)
	}
	return results
}
