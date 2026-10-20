// Package dns provides lightweight DNS metadata intelligence for discovered hostnames.
package dns

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Record holds resolved DNS intelligence for a single hostname.
type Record struct {
	Hostname    string   `json:"hostname"`
	ARecords    []string `json:"a_records,omitempty"`
	AAAARecords []string `json:"aaaa_records,omitempty"`
	CNAME       string   `json:"cname,omitempty"`
	IPs         []string `json:"ips,omitempty"`
}

// Engine performs DNS intelligence gathering with bounded concurrency.
type Engine struct {
	resolver *net.Resolver
	threads  int
}

// NewEngine creates a new DNS Intelligence Engine.
func NewEngine(threads int) *Engine {
	if threads <= 0 {
		threads = 10
	}
	if threads > 50 {
		threads = 50
	}

	return &Engine{
		resolver: net.DefaultResolver,
		threads:  threads,
	}
}

// ResolveHost queries DNS for A, AAAA, and CNAME records for a single hostname.
func (e *Engine) ResolveHost(ctx context.Context, hostname string) Record {
	rec := Record{Hostname: hostname}

	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// 1. IP Lookup (A and AAAA)
	ips, err := e.resolver.LookupIPAddr(lookupCtx, hostname)
	if err == nil {
		for _, ipAddr := range ips {
			ipStr := ipAddr.IP.String()
			rec.IPs = append(rec.IPs, ipStr)
			if ipAddr.IP.To4() != nil {
				rec.ARecords = append(rec.ARecords, ipStr)
			} else {
				rec.AAAARecords = append(rec.AAAARecords, ipStr)
			}
		}
	}

	// 2. CNAME Lookup
	cname, err := e.resolver.LookupCNAME(lookupCtx, hostname)
	if err == nil && cname != "" && !strings.EqualFold(strings.TrimSuffix(cname, "."), hostname) {
		rec.CNAME = strings.TrimSuffix(cname, ".")
	}

	return rec
}

// DetectWildcard checks if a root domain resolves non-existent subdomains (wildcard DNS).
func (e *Engine) DetectWildcard(ctx context.Context, domain string) (bool, []string) {
	randSub := fmt.Sprintf("recon-wc-%d.%s", time.Now().UnixNano(), domain)
	rec := e.ResolveHost(ctx, randSub)
	if len(rec.IPs) > 0 {
		return true, rec.IPs
	}
	return false, nil
}

// ProcessSubdomains resolves DNS metadata for all hosts in subdomainsFile
// and writes structured output to dnsDir.
func (e *Engine) ProcessSubdomains(ctx context.Context, subdomainsFile, dnsDir string, rootDomain ...string) ([]Record, error) {
	if err := os.MkdirAll(dnsDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create dns directory: %w", err)
	}

	// Detect wildcard DNS if rootDomain is provided
	if len(rootDomain) > 0 && rootDomain[0] != "" {
		if isWc, wcIPs := e.DetectWildcard(ctx, rootDomain[0]); isWc {
			_ = writeLines(filepath.Join(dnsDir, "wildcard.txt"), []string{
				fmt.Sprintf("Wildcard DNS detected for %s: %s", rootDomain[0], strings.Join(wcIPs, ", ")),
			})
		}
	}

	f, err := os.Open(subdomainsFile)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open subdomains file: %w", err)
	}
	defer f.Close()

	var hostnames []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		h := strings.TrimSpace(scanner.Text())
		if h != "" {
			hostnames = append(hostnames, h)
		}
	}

	if len(hostnames) == 0 {
		return nil, nil
	}

	// Controlled concurrent resolution
	resultsChan := make(chan Record, len(hostnames))
	jobs := make(chan string, len(hostnames))

	var wg sync.WaitGroup
	workers := e.threads
	if workers > len(hostnames) {
		workers = len(hostnames)
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					rec := e.ResolveHost(ctx, h)
					resultsChan <- rec
				}
			}
		}()
	}

	for _, h := range hostnames {
		jobs <- h
	}
	close(jobs)

	wg.Wait()
	close(resultsChan)

	var records []Record
	allIPs := make(map[string]struct{})
	allARecords := make(map[string]struct{})
	cnames := make([]string, 0)

	for r := range resultsChan {
		records = append(records, r)
		for _, ip := range r.IPs {
			allIPs[ip] = struct{}{}
		}
		for _, a := range r.ARecords {
			allARecords[fmt.Sprintf("%s -> %s", r.Hostname, a)] = struct{}{}
		}
		if r.CNAME != "" {
			cnames = append(cnames, fmt.Sprintf("%s -> %s", r.Hostname, r.CNAME))
		}
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Hostname < records[j].Hostname
	})

	// 1. Write dns-records.json
	data, _ := json.MarshalIndent(records, "", "  ")
	_ = os.WriteFile(filepath.Join(dnsDir, "dns-records.json"), data, 0640)

	// 2. Write ips.txt
	ipList := make([]string, 0, len(allIPs))
	for ip := range allIPs {
		ipList = append(ipList, ip)
	}
	sort.Strings(ipList)
	_ = writeLines(filepath.Join(dnsDir, "ips.txt"), ipList)

	// 3. Write cnames.txt
	sort.Strings(cnames)
	_ = writeLines(filepath.Join(dnsDir, "cnames.txt"), cnames)

	// 4. Write a-records.txt
	aList := make([]string, 0, len(allARecords))
	for a := range allARecords {
		aList = append(aList, a)
	}
	sort.Strings(aList)
	_ = writeLines(filepath.Join(dnsDir, "a-records.txt"), aList)

	return records, nil
}

func writeLines(path string, lines []string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	return w.Flush()
}
