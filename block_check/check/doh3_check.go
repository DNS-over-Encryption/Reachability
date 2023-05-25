package check

import (
	"Block_Check/metrics"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"
	"io"
	"net/http"
	"strconv"
	"strings"
)

func DoH3_Verify(line, queryport, sni, checkTime, iptype, httpMethod, vpn, vpnconfig string) string {
	Target := new(metrics.Result)
	Target.ScanPort = queryport
	Target.ScanType = "DoH3"
	Target.CheckTime = checkTime
	Target.IpType = iptype
	Target.HTTPMethod = httpMethod
	Target.VPNServer = vpn
	Target.VPNConfig = vpnconfig

	var host string
	if len(strings.Split(line, ",")) != 2 {
		Target.HTTPPath = "dns-query"
		host = line
	} else {
		Target.HTTPPath = strings.Split(line, ",")[1]
		host = strings.Split(line, ",")[0]
	}

	var answerList string
	var dns_flag bool
	if sni == "true" {
		Target.ServerDomain = host
		dns_flag, answerList = metrics.IP_query(Target.ServerDomain, iptype)
		if dns_flag == false {
			return metrics.WriteResult(Target, true, "Pre DNS", answerList)
		}
	} else {
		answerList = host
	}

	outResult := ""
	for _, value := range strings.Split(answerList, ";;;") {
		Target.ServerIp = value

		// 建立UDP连接
		udpconn, udperr := metrics.UDP_conn(Target.ServerIp, Target.ScanPort, iptype)
		if udperr != "" {
			outResult += metrics.WriteResult(Target, true, "UDP", udperr) + "\n"
			continue
		}
		_ = udpconn.Close()

		// 建立QUIC连接
		quicSeeion, quicerr := metrics.QUIC_conn(Target.ServerIp, Target.ServerDomain, Target.ScanPort, Target.IpType, sni)
		if quicerr != "" {
			outResult += metrics.WriteResult(Target, true, "QUIC", quicerr) + "\n"
			continue
		}

		// 保存证书链
		certchain := ""
		for _, cert := range quicSeeion.ConnectionState().TLS.PeerCertificates {
			var block = &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}

			aa := pem.EncodeToMemory(block)
			enc := base64.StdEncoding.EncodeToString(aa)
			certchain = certchain + "###" + enc // 分隔符 ","
		}
		Target.RawCertChain = strings.TrimLeft(certchain, "###")

		// 检查证书
		certvalid, certerr := metrics.CheckCertsChain(quicSeeion.ConnectionState().TLS.PeerCertificates, Target.ServerDomain, sni)
		Target.CertValid = certvalid
		Target.CertErr = certerr
		Target.TLSVersion = metrics.TLSVerDict[quicSeeion.ConnectionState().TLS.Version]

		var httpreq *http.Request
		var httperr error
		httpbuf, _ := metrics.Raw_dns_query().Pack()
		// 指定HTTP请求方法
		var http_host string
		if iptype == "ipv4" {
			http_host = Target.ServerIp + ":" + Target.ScanPort
		} else {
			http_host = "[" + Target.ServerIp + "]" + ":" + Target.ScanPort
		}

		if httpMethod == "POST" {
			PostBody := bytes.NewReader(httpbuf)
			server_url := "https://" + http_host + "/" + Target.HTTPPath
			httpreq, httperr = http.NewRequest(http.MethodPost, server_url, PostBody)
			if httperr != nil {
				outResult += metrics.WriteResult(Target, false, "HTTP Wrap", httperr.Error()) + "\n"
				continue
			}
		} else {
			server_url := "https://" + http_host + "/" + Target.HTTPPath + "?dns=" + base64.RawURLEncoding.EncodeToString(httpbuf)
			httpreq, httperr = http.NewRequest(http.MethodGet, server_url, nil)
			if httperr != nil {
				outResult += metrics.WriteResult(Target, false, "HTTP Wrap", httperr.Error()) + "\n"
				continue
			}
		}

		httpreq.Host = Target.ServerDomain // Set the Host header to the domain name
		if sni == "true" {
			httpreq.Host = Target.ServerDomain // Set the Host header to the domain name
		}

		tlsCfg := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         Target.ServerDomain,
			NextProtos:         []string{"h3", "h3-29"},
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		}

		h3Client := http.Client{
			Timeout: timeout,
			Transport: &http3.RoundTripper{
				TLSClientConfig: tlsCfg,
				//Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				//
				//	return quicsesion, nil
				//},
			},
		}

		resp, http3err := h3Client.Do(httpreq)
		if http3err != nil {
			outResult += metrics.WriteResult(Target, true, "HTTP3", http3err.Error()) + "\n"
			continue
		}

		// 解析DoH3响应
		if resp == nil {
			outResult += metrics.WriteResult(Target, true, "HTTP Response", "HTTP Response None") + "\n"
			continue
		} else {
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				bodyBytes, _ := io.ReadAll(resp.Body)
				dnsresponse := dns.Msg{}
				dnsresponse.Unpack(bodyBytes)
				check_flag, dns_answer, check_result := metrics.DNS_answer_check(&dnsresponse)

				if check_flag {
					Target.QueryResult = dns_answer
					if check_result == "success" {
						outResult += metrics.WriteResult(Target, false, "Success", "None") + "\n"
					} else {
						outResult += metrics.WriteResult(Target, false, "DNS Answer", check_result) + "\n"
					}
				} else {
					outResult += metrics.WriteResult(Target, true, "DNS Answer", check_result) + "\n"
				}

			} else {
				StatusCode := strconv.Itoa(resp.StatusCode)
				outResult += metrics.WriteResult(Target, true, "HTTP Response", StatusCode) + "\n"
			}
		}
	}

	outResult = strings.TrimRight(outResult, "\n")
	return outResult
}
