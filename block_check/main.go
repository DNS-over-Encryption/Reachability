package main

import (
	"Block_Check/check"
	"Block_Check/metrics"
	"bufio"
	"flag"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"os"
	"strconv"
	"sync"
	"time"
)

func run(jobs <-chan string, queryType, queryPort, sni, ScanFile, checkTime, ipType, httpVer, httpMethod, vpn, vpnconfig string, wg *sync.WaitGroup, limiter *rate.Limiter, ctx context.Context) {
	defer wg.Done()
	scanF, err_ := os.Create(ScanFile)
	if err_ != nil {
		fmt.Println(err_.Error())
	}
	for line := range jobs {

		limiter.Wait(ctx)
		switch queryType {
		case "dot":
			result := check.DoT_Verify(line, queryPort, sni, checkTime, ipType, vpn, vpnconfig)
			scanF.WriteString(result)
			scanF.WriteString("\n")

		case "doh":
			result := check.DoH_Verify(line, queryPort, sni, checkTime, ipType, httpVer, httpMethod, vpn, vpnconfig)
			scanF.WriteString(result)
			scanF.WriteString("\n")

		case "doq":
			result := check.DoQ_Verify(line, queryPort, sni, checkTime, ipType, vpn, vpnconfig)
			scanF.WriteString(result)
			scanF.WriteString("\n")

		case "doh3":
			result := check.DoH3_Verify(line, queryPort, sni, checkTime, ipType, httpMethod, vpn, vpnconfig)
			scanF.WriteString(result)
			scanF.WriteString("\n")

		default:
			fmt.Println(line + "parameter err")
			os.Exit(3)

		}

	}

	scanF.Close()

}

func main() {
	var numThreads = flag.Int("n", 100, "Number of threads")
	var inputFile = flag.String("i", "./input.txt", "Input File")
	var resultDir = flag.String("o", "./result/", "Output Dir")
	var queryType = flag.String("t", "doq", "dot or doh or doq or doh3")
	var queryPort = flag.String("p", "853", "Scan Port")

	var sni = flag.String("s", "true", "SNI")
	var ipType = flag.String("a", "ipv4", "Scan ipv4 or ipv6")
	var httpVer = flag.String("h", "h1", "HTTP Version")
	var httpMethod = flag.String("m", "GET", "HTTP Method")

	var checkTime = flag.String("f", "2023-05-26", "Scan Flag")
	var vpn = flag.String("v", "VPN Server", "IP address of VPN server")
	var vpnconfig = flag.String("c", "VPN Config", "VPN config file")

	startTime := time.Now()
	fmt.Println("start scan at:", startTime)

	flag.Parse()

	QPS := *numThreads
	jobs := make(chan string)
	var wg sync.WaitGroup
	limiter := rate.NewLimiter(rate.Limit(QPS), 1)
	ctx := context.Background()

	for w := 0; w < *numThreads; w++ {
		go func(wgScoped *sync.WaitGroup, limiterScoped *rate.Limiter, i int, ctxScoped context.Context) {
			wgScoped.Add(1)

			scanFile := *resultDir + "scan-" + strconv.Itoa(i) + ".txt"

			run(jobs, *queryType, *queryPort, *sni, scanFile, *checkTime, *ipType, *httpVer, *httpMethod, *vpn, *vpnconfig, wgScoped, limiterScoped, ctxScoped)
		}(&wg, limiter, w, ctx)
	}

	inputf, err := os.Open(*inputFile)
	if err != nil {
		err.Error()
	}
	scanner := bufio.NewScanner(inputf)

	for scanner.Scan() {
		jobs <- scanner.Text()
	}
	close(jobs)
	wg.Wait()

	inputf.Close()

	mergeErr := metrics.FileMerge(*resultDir+"scan-*", *resultDir+"result_scan.txt")
	if mergeErr != "success" {
		fmt.Println("scan file merge err")
	}

	endTime := time.Now()
	fmt.Println("end scan at:", endTime)
	fmt.Println("duration:", time.Since(startTime).String())

}
