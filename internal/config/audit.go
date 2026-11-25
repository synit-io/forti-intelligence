package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v4"
)

type AuditConfig struct {
	Syslog AuditSyslogConfig `yaml:"syslog,omitempty"`
}

func (c *AuditConfig) UnmarshalYAML(node *yaml.Node) error {
	type plain AuditConfig
	if err := node.Load((*plain)(c), yaml.WithKnownFields()); err != nil {
		return fmt.Errorf("server.audit: %w", err)
	}
	return nil
}

type AuditSyslogConfig struct {
	Target string `yaml:"target,omitempty"`
	CAFile string `yaml:"ca_file,omitempty"`
}

// Endpoint validates the receiver settings without contacting the receiver.
// An empty address disables forwarding and a nil TLS config selects plain TCP.
func (c AuditSyslogConfig) Endpoint() (address string, tlsConfig *tls.Config, err error) {
	target := strings.TrimSpace(c.Target)
	if target == "" {
		if c.CAFile != "" {
			return "", nil, fmt.Errorf("server.audit.syslog.ca_file requires a tls:// target")
		}
		return "", nil, nil
	}

	endpoint, err := url.Parse(target)
	if err != nil || (endpoint.Scheme != "tls" && endpoint.Scheme != "tcp") ||
		endpoint.User != nil || endpoint.Path != "" || endpoint.ForceQuery || endpoint.RawQuery != "" || strings.Contains(target, "#") {
		return "", nil, fmt.Errorf("server.audit.syslog.target must be tls://host:port or tcp://host:port")
	}
	host, port, err := net.SplitHostPort(endpoint.Host)
	if err != nil || host == "" {
		return "", nil, fmt.Errorf("server.audit.syslog.target requires a host and port")
	}
	if strings.HasPrefix(endpoint.Host, "[") {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() {
			return "", nil, fmt.Errorf("server.audit.syslog.target requires an IPv6 address inside brackets")
		}
	}
	if portNumber, err := strconv.ParseUint(port, 10, 16); err != nil || portNumber == 0 {
		return "", nil, fmt.Errorf("server.audit.syslog.target port must be between 1 and 65535")
	}
	if endpoint.Scheme == "tcp" {
		if c.CAFile != "" {
			return "", nil, fmt.Errorf("server.audit.syslog.ca_file requires a tls:// target")
		}
		return endpoint.Host, nil, nil
	}

	tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		certs, err := os.ReadFile(c.CAFile)
		if err != nil {
			return "", nil, fmt.Errorf("server.audit.syslog.ca_file: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return "", nil, fmt.Errorf("server.audit.syslog.ca_file could not load system trust: %w", err)
		}
		if !roots.AppendCertsFromPEM(certs) {
			return "", nil, fmt.Errorf("server.audit.syslog.ca_file has no readable PEM certificates")
		}
		tlsConfig.RootCAs = roots
	}
	return endpoint.Host, tlsConfig, nil
}
