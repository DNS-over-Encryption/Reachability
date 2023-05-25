package check

import (
	"Block_Check/metrics"
	"encoding/base64"
	"encoding/pem"
	"github.com/miekg/dns"
	"strings"
	"time"
)

const timeout = 10 * time.Second

func DoT_Verify(line, queryport, sni, checkTime, iptype, vpn, vpnconfig string) string {
	Target := new(metrics.Result)
	Target.ScanPort = queryport
	Target.ScanType = "DoT"
	Target.CheckTime = checkTime
	Target.IpType = iptype
	Target.VPNServer = vpn
	Target.VPNConfig = vpnconfig

	var answerList string
	var dns_flag bool
	if sni == "true" {
		Target.ServerDomain = line
		dns_flag, answerList = metrics.IP_query(Target.ServerDomain, iptype)
		if dns_flag == false {
			return metrics.WriteResult(Target, true, "Pre DNS", answerList)
		}
	} else {
		answerList = line
	}
	// 向每一个IP地址发送DoT查询
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
			certchain = certchain + "###" + enc // 分隔符 ","
		}
		Target.RawCertChain = strings.TrimLeft(certchain, "###")

		// 检查证书
		certvalid, certerr := metrics.CheckCertsChain(tlsConn.ConnectionState().PeerCertificates, Target.ServerDomain, sni)
		Target.CertValid = certvalid
		Target.CertErr = certerr
		Target.TLSVersion = metrics.TLSVerDict[tlsConn.ConnectionState().Version]

		// 发送DoT查询
		cn := dns.Conn{Conn: tlsConn}
		_ = cn.SetDeadline(time.Now().Add(timeout))

		dnserr := cn.WriteMsg(metrics.Raw_dns_query())
		if dnserr != nil {
			outResult += metrics.WriteResult(Target, true, "DNS Query", dnserr.Error()) + "\n"
			continue
		}

		reply, queryerr := cn.ReadMsg()
		if queryerr != nil {
			outResult += metrics.WriteResult(Target, true, "DNS Answer", queryerr.Error()) + "\n"
			continue
		}

		// 解析DoT响应
		check_flag, dns_answer, check_result := metrics.DNS_answer_check(reply)

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

	}

	outResult = strings.TrimRight(outResult, "\n")
	return outResult
}
