package check

import (
	"Block_Check/metrics"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const (
	QueryDomain = "example.com"
	DohJsonType = "application/dns-json"
	DohDnsType  = "application/dns-message"
	GetQuery    = "?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
	JsonQuery   = "?name=example.com&type=A"
)

func DoH_Verify(line, queryport, sni, checkTime, iptype, httpVer, httpMethod, vpn, vpnconfig string) string {
	Target := new(metrics.Result)
	Target.ScanPort = queryport
	Target.ScanType = "DoH"
	Target.CheckTime = checkTime
	Target.IpType = iptype
	Target.HTTPMethod = httpMethod
	Target.HTTPVersion = httpVer
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

	// 向每一个IP地址发送DoH查询
	outResult := ""
	for _, value := range strings.Split(answerList, ";;;") {
		Target.ServerIp = value

		// 建立TCP连接
		tcpconn, tcperr := metrics.TCP_conn(Target.ServerIp, Target.ScanPort, iptype)
		if tcperr != "" {
			outResult += metrics.WriteResult(Target, true, "TCP", tcperr) + "\n"
			continue
		}

		// 建立TLS连接
		tlsConn, tlserr := metrics.TLS_conn(Target.ServerDomain, sni, tcpconn)
		if tlserr != "" {
			outResult += metrics.WriteResult(Target, true, "TLS", tlserr) + "\n"
			continue
		}

		// 保存证书链
		certchain := ""
		for _, cert := range tlsConn.ConnectionState().PeerCertificates {
			var block = &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}

			aa := pem.EncodeToMemory(block)
			enc := base64.StdEncoding.EncodeToString(aa)
			certchain = certchain + "###" + enc
		}
		Target.RawCertChain = strings.TrimLeft(certchain, "###")

		// 检查证书
		certvalid, certerr := metrics.CheckCertsChain(tlsConn.ConnectionState().PeerCertificates, Target.ServerDomain, sni)
		Target.CertValid = certvalid
		Target.CertErr = certerr
		Target.TLSVersion = metrics.TLSVerDict[tlsConn.ConnectionState().Version]

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

		httpreq.Header.Set("Content-Type", DohDnsType)
		if sni == "true" {
			httpreq.Host = Target.ServerDomain // Set the Host header to the domain name
		}

		// 指定HTTP版本
		var Client http.Client
		if httpVer == "h1" {
			transport := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         Target.ServerDomain,
					MaxVersion:         0,
				},
			}
			Client = http.Client{
				Timeout:   timeout,
				Transport: transport,
			}
		} else {
			transport := &http2.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         Target.ServerDomain,
					MaxVersion:         0,
				},
			}
			Client = http.Client{
				Timeout:   timeout,
				Transport: transport,
			}
		}

		// 发送DoH请求
		resp, dnserr := Client.Do(httpreq)
		if dnserr != nil {
			outResult += metrics.WriteResult(Target, false, "HTTP Request", dnserr.Error()) + "\n"
			continue
		}

		// 解析DoH响应
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
