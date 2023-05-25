package check

import (
	"Block_Check/metrics"
	"encoding/base64"
	"encoding/pem"
	_ "github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"io"
	"strings"
)

func DoQ_Verify(line, queryport, sni, checkTime, iptype, vpn, vpnconfig string) string {
	Target := new(metrics.Result)
	Target.ScanPort = queryport
	Target.ScanType = "DoQ"
	Target.CheckTime = checkTime
	Target.IpType = iptype
	Target.VPNServer = vpn
	Target.VPNConfig = vpnconfig

	var answerList string
	var dnsflag bool
	if sni == "true" {
		Target.ServerDomain = line
		dnsflag, answerList = metrics.IP_query(Target.ServerDomain, iptype)
		if dnsflag == false {
			return metrics.WriteResult(Target, true, "Pre DNS", answerList)
		}
	} else {
		answerList = line
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

		// 打开QUIC会话
		openStreamCtx, openStreamCancel := context.WithTimeout(context.Background(), timeout)
		defer openStreamCancel()
		stream, openerr := quicSeeion.OpenStreamSync(openStreamCtx)
		if openerr != nil {
			outResult += metrics.WriteResult(Target, true, "QUIC", openerr.Error()) + "\n"
			continue
		}

		req := metrics.Raw_dns_query()
		req.Id = 0
		reqbuf, _ := req.Pack()

		// 发送DoQ查询
		_, doqerr := stream.Write(reqbuf)
		if doqerr != nil {
			outResult += metrics.WriteResult(Target, true, "DNS Query", doqerr.Error()) + "\n"
			continue
		}
		_ = stream.Close()

		respBuf, err := io.ReadAll(stream)
		if err != nil {
			outResult += metrics.WriteResult(Target, true, "DNS Answer", err.Error()) + "\n"
			continue
		}

		reply := dns.Msg{}
		err = reply.Unpack(respBuf)
		if err != nil {
			outResult += metrics.WriteResult(Target, true, "DNS Answer", err.Error()) + "\n"
			continue
		}

		check_flag, dns_answer, check_result := metrics.DNS_answer_check(&reply)

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
