package metrics

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"os/exec"
)

var TLSVerDict = map[uint16]string{
	tls.VersionTLS10: "tls1_0",
	tls.VersionTLS11: "tls1_1",
	tls.VersionTLS12: "tls1_2",
	tls.VersionTLS13: "tls1_3",
}

type Result struct {
	ServerIp     string `json:"server_ip"`
	ServerDomain string `json:"server_domain"`
	ScanPort     string `json:"scan_port"`

	CheckTime string `json:"check_time"`
	IpType    string `json:"ip_type"`
	ScanType  string `json:"scan_type"`

	Block       bool   `json:"block"`
	BlockType   string `json:"block_type"`
	BlockErr    string `json:"block_err"`
	QueryResult string `json:"query_result"`

	CertValid    bool   `json:"cert_valid"`
	RawCertChain string `json:"raw_cert_chain"`
	CertErr      string `json:"cert_err"`
	TLSVersion   string `json:"tls_version"`

	HTTPPath    string `json:"http_path"`
	HTTPVersion string `json:"http_version"`
	HTTPMethod  string `json:"http_method"`

	VPNServer string `json:"vpn_server"`
	VPNConfig string `json:"vpn_config"`
}

func FileMerge(originalFile string, finalFile string) string {
	in := bytes.NewBuffer(nil)
	cmd := exec.Command("sh")
	cmd.Stdin = in
	in.WriteString("for i in " + originalFile + ";do cat $i >> " + finalFile + ";done\n")
	in.WriteString("sleep 5s\n")
	in.WriteString("rm " + originalFile + "\n")
	in.WriteString("exit\n")
	if err := cmd.Run(); err != nil {
		return "err"
	} else {
		return "success"
	}
}

func WriteResult(Target *Result, Block bool, ErrType string, connErr string) string {
	Target.Block = Block
	Target.BlockType = ErrType
	Target.BlockErr = connErr
	outresult, _ := json.Marshal(Target)
	return string(outresult)
}
