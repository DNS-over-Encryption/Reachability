package metrics

import (
	"crypto/tls"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"net"
	"strings"
	"time"
)

var DefaultQUICVersions = []quic.VersionNumber{
	quic.Version1,
	quic.VersionDraft29,
}
var defaultDoQVersions = []string{"doq", "h3", "h3-29"}

const timeout = 10 * time.Second

func Raw_dns_query() *dns.Msg {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: "example.com" + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	return &req
}

func TCP_conn(ip, port, iptype string) (*net.Conn, string) {

	// 建立tcp连接
	var tcpconn net.Conn
	var tcperr error
	dialer := net.Dialer{Timeout: timeout}
	if iptype == "ipv4" {
		fullAddr := ip + ":" + port
		tcpconn, tcperr = dialer.Dial("tcp", fullAddr)
	} else {
		fullAddr := "[" + ip + "]" + ":" + port
		tcpconn, tcperr = dialer.Dial("tcp6", fullAddr)
	}
	if tcperr != nil {
		return &tcpconn, tcperr.(*net.OpError).Err.Error()
	} else {
		return &tcpconn, ""
	}
}

func UDP_conn(ip, port, iptype string) (net.Conn, string) {

	// 建立udp连接
	var udpconn net.Conn
	var udperr error
	dialer := net.Dialer{Timeout: timeout}
	if iptype == "ipv4" {
		fullAddr := ip + ":" + port
		udpconn, udperr = dialer.Dial("udp", fullAddr)
	} else {
		fullAddr := "[" + ip + "]" + ":" + port
		udpconn, udperr = dialer.Dial("udp6", fullAddr)
	}
	if udperr != nil {
		return udpconn, udperr.(*net.OpError).Err.Error()
	} else {
		return udpconn, ""
	}
}

func TLS_conn(domain, sni string, tcpconn *net.Conn) (*tls.Conn, string) {
	// 建立TLS连接
	var tlsConfig *tls.Config
	if sni == "true" {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		}
	} else {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		}
	}

	tlsConn := tls.Client(*tcpconn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(timeout))
	tlserr := tlsConn.Handshake()

	if tlserr != nil {
		return tlsConn, tlserr.Error()
	} else {
		return tlsConn, ""
	}

}

func QUIC_conn(ip, domain, port, iptype, sni string) (quic.Connection, string) {
	quicCfg := &quic.Config{
		HandshakeIdleTimeout: timeout,
		Versions:             DefaultQUICVersions,
	}

	var tlsConfig *tls.Config
	if sni == "true" {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
			NextProtos:         defaultDoQVersions,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		}
	} else {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         defaultDoQVersions,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		}
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), timeout)
	defer dialCancel()

	var quicsession quic.Connection
	var quicerr error

	if iptype == "ipv4" {
		fullAddr := ip + ":" + port
		quicsession, quicerr = quic.DialAddrContext(dialCtx, fullAddr, tlsConfig, quicCfg)
	} else {
		fullAddr := "[" + ip + "]" + ":" + port
		quicsession, quicerr = quic.DialAddrContext(dialCtx, fullAddr, tlsConfig, quicCfg)
	}

	if quicerr != nil {
		return quicsession, quicerr.Error()
	} else {
		return quicsession, ""
	}

}

func IP_query(domain, iptype string) (bool, string) {
	c := dns.Client{
		Timeout: timeout,
	}
	m := dns.Msg{}
	if iptype == "ipv4" {
		m.SetQuestion(domain+".", dns.TypeA)
	} else {
		m.SetQuestion(domain+".", dns.TypeAAAA)
	}

	m.RecursionDesired = true
	response, _, err := c.Exchange(&m, "8.8.8.8:53")
	if err != nil {
		return false, "Pre DNS ERR"
	}

	if len(response.Answer) < 1 {
		return false, dns.RcodeToString[response.Rcode] + ";No DNS Answer"
	}

	answerList := ""
	for _, value := range response.Answer {
		if iptype == "ipv4" {
			record, isType := value.(*dns.A)
			if isType {
				answerList += record.A.String() + ";;;"
			}
		} else {
			record, isType := value.(*dns.AAAA)
			if isType {
				answerList += record.AAAA.String() + ";;;"
			}
		}
	}
	answerList = strings.TrimRight(answerList, ";;;")

	if answerList == "" {
		return false, dns.RcodeToString[response.Rcode] + ";No DNS Answer"
	}
	return true, answerList
}

func DNS_answer_check(reply *dns.Msg) (bool, string, string) {
	if len(reply.Answer) < 1 {
		return false, "", dns.RcodeToString[reply.Rcode] + ";No DNS Answer"
	}

	dnsAnswer := ""
	for _, value := range reply.Answer {
		record, isType := value.(*dns.A)
		if isType {
			dnsAnswer += record.A.String() + ";"
		}

	}
	dnsAnswer = strings.TrimRight(dnsAnswer, ";")

	if dnsAnswer != "93.184.216.34" {
		return true, dnsAnswer, dns.RcodeToString[reply.Rcode] + ";Err DNS Answer"
	} else {
		return true, dnsAnswer, "success"
	}
}