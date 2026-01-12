/*
File: hosts.go
Version: 1.16.1
Description: Main entry point for Hosts Cache. Handles runtime lookups and auto-refresh orchestration.
             UPDATED: Replaced linear filter scan with Radix Trie (cidranger) for O(1) IP filtering.
             UPDATED: Added GetHostnames for fast reverse lookup in logging.
             FIXED: Wildcard matching restricted to blocked IPs (0.0.0.0/loopback) to prevent search domain collisions.
*/

package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/yl2chen/cidranger"
)

type HostsCache struct {
	sync.RWMutex
	forward map[string][]net.IP
	reverse map[string][]string
	allowed map[string][]net.IP // Allowlist map
	
	// Optimized IP Trie
	ipRanger cidranger.Ranger

	paths           []string
	urls            []string
	wildcard        bool
	performOpt      bool
	optimizeTLD     bool
	filterResponses bool
	defaultTTL      uint32
	cacheDir        string

	fileMtimes map[string]time.Time
	urlMetas   map[string]urlMeta

	client *http.Client
}

func NewHostsCache() *HostsCache {
	return &HostsCache{
		forward:    make(map[string][]net.IP),
		reverse:    make(map[string][]string),
		allowed:    make(map[string][]net.IP),
		ipRanger:   cidranger.NewPCTrieRanger(), // Path-Compressed Trie
		fileMtimes: make(map[string]time.Time),
		urlMetas:   make(map[string]urlMeta),
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		defaultTTL: 0,
	}
}

func (hc *HostsCache) SetTTL(ttl uint32) {
	hc.Lock()
	defer hc.Unlock()
	hc.defaultTTL = ttl
}

// LoadFromCache merges a loaded SourceCache into the active runtime cache.
func (hc *HostsCache) LoadFromCache(paths []string, urls []string, sourceCache SourceCache, wildcard bool, optimize bool, optimizeTLD bool, filterResponses bool) (int, int) {
	start := time.Now()

	newForward := make(map[string][]net.IP)
	newReverse := make(map[string][]string)
	newAllowed := make(map[string][]net.IP)
	
	// Build new Ranger
	newRanger := cidranger.NewPCTrieRanger()
	filterCount := 0

	newFileMtimes := make(map[string]time.Time)
	newUrlMetas := make(map[string]urlMeta)

	totalSources := 0

	merge := func(key string) {
		if data, ok := sourceCache[key]; ok {
			totalSources++
			for k, v := range data.Forward {
				newForward[k] = append(newForward[k], v...)
			}
			for k, v := range data.Reverse {
				newReverse[k] = append(newReverse[k], v...)
			}
			// Merge Allowlist
			for k, v := range data.Allowed {
				newAllowed[k] = append(newAllowed[k], v...)
			}
			
			// Insert Filters into Ranger
			for _, f := range data.Filters {
				_ = newRanger.Insert(cidranger.NewBasicRangerEntry(*f))
				filterCount++
			}
			
			if !data.MTime.IsZero() {
				newFileMtimes[key] = data.MTime
			}
			newUrlMetas[key] = data.Meta
		} else {
			LogWarn("[HOSTS] Source not found in cache during merge: %s", key)
		}
	}

	for _, path := range paths {
		merge(path)
	}
	for _, url := range urls {
		merge(url)
	}

	if wildcard && optimize {
		hc.optimize(newForward, newReverse, newAllowed, optimizeTLD)
	}

	hc.Lock()
	hc.forward = newForward
	hc.reverse = newReverse
	hc.allowed = newAllowed
	hc.ipRanger = newRanger
	hc.paths = paths
	hc.urls = urls
	hc.wildcard = wildcard
	hc.performOpt = optimize
	hc.optimizeTLD = optimizeTLD
	hc.filterResponses = filterResponses
	hc.fileMtimes = newFileMtimes
	hc.urlMetas = newUrlMetas
	hc.Unlock()

	LogInfo("[HOSTS] Cache assembled from %d sources in %v (%d names, %d allowed, %d filters)", 
		totalSources, time.Since(start), len(newForward), len(newAllowed), filterCount)
	return len(newForward), len(newReverse)
}

// Load triggers a fresh load of the specified paths and URLs.
func (hc *HostsCache) Load(paths []string, urls []string, wildcard bool, optimize bool, optimizeTLD bool, filterResponses bool) {
	cache := BatchLoadSources(paths, urls, hc.cacheDir)
	names, ips := hc.LoadFromCache(paths, urls, cache, wildcard, optimize, optimizeTLD, filterResponses)
	LogInfo("[HOSTS] Refresh complete: %d names, %d IPs", names, ips)
}

func (hc *HostsCache) StartAutoRefresh(ctx context.Context, checkInterval time.Duration) {
	if len(hc.paths) == 0 && len(hc.urls) == 0 {
		return
	}
	LogInfo("[HOSTS] Starting auto-refresh for %d files, %d URLs (Interval: %v)", len(hc.paths), len(hc.urls), checkInterval)
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hc.checkUpdates()
		}
	}
}

func (hc *HostsCache) HasRemote() bool {
	hc.RLock()
	defer hc.RUnlock()
	return len(hc.urls) > 0
}

func (hc *HostsCache) checkUpdates() {
	shouldReload := false
	for _, path := range hc.paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		hc.RLock()
		lastMod, known := hc.fileMtimes[path]
		hc.RUnlock()
		if !known || info.ModTime().After(lastMod) {
			LogInfo("[HOSTS] File changed: %s", path)
			shouldReload = true
			break
		}
	}
	if !shouldReload {
		for _, url := range hc.urls {
			if hc.checkURLChanged(url) {
				LogInfo("[HOSTS] URL changed: %s", url)
				shouldReload = true
				break
			}
		}
	}
	if shouldReload {
		hc.RLock()
		w := hc.wildcard
		o := hc.performOpt
		t := hc.optimizeTLD
		fr := hc.filterResponses
		hc.RUnlock()
		hc.Load(hc.paths, hc.urls, w, o, t, fr)
	}
}

func (hc *HostsCache) checkURLChanged(url string) bool {
	hc.RLock()
	meta, known := hc.urlMetas[url]
	hc.RUnlock()
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false
	}
	if known {
		if meta.ETag != "" {
			req.Header.Set("If-None-Match", meta.ETag)
		}
		if meta.LastModified != "" {
			req.Header.Set("If-Modified-Since", meta.LastModified)
		}
	}
	resp, err := hc.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode != http.StatusNotModified && resp.StatusCode == http.StatusOK
}

// GetHostnames returns all known hostnames for a given IP from the cache.
func (hc *HostsCache) GetHostnames(ip net.IP) []string {
	hc.RLock()
	defer hc.RUnlock()
	return hc.reverse[ip.String()]
}

// FilterResponse filters IPs in a DNS response msg using the Radix Trie.
func (hc *HostsCache) FilterResponse(msg *dns.Msg, qName, ruleName, clientInfo string) bool {
	if msg == nil || len(msg.Answer) == 0 {
		return false
	}

	// Fast check
	hc.RLock()
	if !hc.filterResponses {
		hc.RUnlock()
		return false
	}
	ranger := hc.ipRanger
	hc.RUnlock()

	var newAnswer []dns.RR
	modified := false
	
	seenA := false
	seenAAAA := false

	for _, rr := range msg.Answer {
		var ip net.IP
		switch r := rr.(type) {
		case *dns.A:
			ip = r.A
			seenA = true
		case *dns.AAAA:
			ip = r.AAAA
			seenAAAA = true
		}

		if ip != nil {
			// Fast Trie Lookup
			networks, err := ranger.ContainingNetworks(ip)
			if err == nil && len(networks) > 0 {
				modified = true
				match := networks[len(networks)-1].Network()
				LogInfo("[HOSTS] FILTERED: Removed IP %s from upstream response for %s | Trigger: %s | Rule: %s | Client: %s", 
					ip.String(), qName, match.String(), ruleName, clientInfo)
			} else {
				newAnswer = append(newAnswer, rr)
			}
		} else {
			newAnswer = append(newAnswer, rr)
		}
	}

	if modified {
		msg.Answer = newAnswer
		
		if len(msg.Answer) == 0 {
			LogInfo("[HOSTS] BLOCKED: %s -> All IPs filtered, injecting block record | Rule: %s | Client: %s",
				qName, ruleName, clientInfo)
			
			var qType uint16
			if len(msg.Question) > 0 {
				qType = msg.Question[0].Qtype
			}

			if qType == dns.TypeA || (qType == 0 && seenA) {
				rr := new(dns.A)
				rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: hc.defaultTTL}
				rr.A = net.IPv4(0, 0, 0, 0)
				msg.Answer = append(msg.Answer, rr)
			} else if qType == dns.TypeAAAA || (qType == 0 && seenAAAA) {
				rr := new(dns.AAAA)
				rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: hc.defaultTTL}
				rr.AAAA = net.ParseIP("::")
				msg.Answer = append(msg.Answer, rr)
			}
		}
	}

	return modified
}

// Lookup queries the hosts cache.
func (hc *HostsCache) Lookup(qName string, qType uint16, wildcard bool, clientInfo, ruleName string) ([]dns.RR, bool) {
	hc.RLock()
	defer hc.RUnlock()
	
	// --- 1. Allowlist Check (Wins over Blocklist) ---
	var allowedIPs []net.IP
	allowedFound := false
	matchType := ""
	matchedName := ""

	if matches, ok := hc.allowed[qName]; ok {
		allowedIPs = matches
		matchType = "exact-allow"
		matchedName = qName
		allowedFound = true
	} else if wildcard {
		curr := qName
		for {
			idx := strings.IndexByte(curr, '.')
			if idx == -1 {
				break
			}
			parent := curr[idx+1:]
			if parent == "" {
				break
			}

			if matches, ok := hc.allowed[parent]; ok {
				allowedIPs = matches
				matchType = "wildcard-allow"
				matchedName = parent
				allowedFound = true
				break
			}
			curr = parent
		}
	}

	if allowedFound {
		if hc.filterResponses {
			allowedIPs = hc.applyIPFiltersInternal(allowedIPs, qName, ruleName, clientInfo)
		}

		if len(allowedIPs) == 0 {
			LogInfo("[HOSTS] ALLOWLIST -> BLOCKED: %s (Type: %s) -> All IPs filtered out | Rule: %s | Client: %s",
				qName, dns.TypeToString[qType], ruleName, clientInfo)
			
			var answers []dns.RR
			if qType == dns.TypeA {
				rr := new(dns.A)
				rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: hc.defaultTTL}
				rr.A = net.IPv4(0, 0, 0, 0)
				answers = append(answers, rr)
			} else if qType == dns.TypeAAAA {
				rr := new(dns.AAAA)
				rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: hc.defaultTTL}
				rr.AAAA = net.ParseIP("::")
				answers = append(answers, rr)
			}
			return answers, true
		} else {
			isBypass := false
			for _, ip := range allowedIPs {
				if isBlockedIP(ip) {
					isBypass = true
					break
				}
			}

			if isBypass {
				LogInfo("[HOSTS] ALLOWLIST: %s (Type: %s) -> Matched: %s (%s) | Rule: %s | Client: %s", 
					qName, dns.TypeToString[qType], matchedName, matchType, ruleName, clientInfo)
				return nil, false
			}

			return hc.generateRRs(qName, qType, allowedIPs, matchType, matchedName, ruleName, clientInfo)
		}
	}

	// --- 2. Standard Forward/Blocklist Check ---
	var ips []net.IP
	found := false

	if matches, ok := hc.forward[qName]; ok {
		ips = matches
		matchType = "exact"
		matchedName = qName
		found = true
	} else if wildcard {
		curr := qName
		for {
			idx := strings.IndexByte(curr, '.')
			if idx == -1 {
				break
			}
			parent := curr[idx+1:]
			if parent == "" {
				break
			}

			if matches, ok := hc.forward[parent]; ok {
				// Only match wildcard if the parent is a BLOCKED IP (0.0.0.0, etc.)
				// This avoids issues with search domains (like "home" -> 192.168.1.1)
				// capturing all subdomains as wildcards.
				hasBlockedIP := false
				for _, ip := range matches {
					if isBlockedIP(ip) {
						hasBlockedIP = true
						break
					}
				}

				if hasBlockedIP {
					ips = matches
					matchType = "wildcard"
					matchedName = parent
					found = true
					break
				}
			}
			curr = parent
		}
	}

	if !found {
		return nil, false
	}

	if hc.filterResponses {
		ips = hc.applyIPFiltersInternal(ips, qName, ruleName, clientInfo)
	}

	isBlocked := false
	if len(ips) == 0 {
		isBlocked = true
	} else {
		for _, ip := range ips {
			if isBlockedIP(ip) {
				isBlocked = true
				break
			}
		}
	}

	ttl := hc.defaultTTL

	if isBlocked {
		var answers []dns.RR
		if qType == dns.TypeA {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
			rr.A = net.IPv4(0, 0, 0, 0)
			answers = append(answers, rr)
		} else if qType == dns.TypeAAAA {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
			rr.AAAA = net.ParseIP("::")
			answers = append(answers, rr)
		}
		LogInfo("[HOSTS] BLOCKED: %s (Type: %s) -> Matched: %s (%s) | Rule: %s | Client: %s", 
			qName, dns.TypeToString[qType], matchedName, matchType, ruleName, clientInfo)
		return answers, true
	}

	return hc.generateRRs(qName, qType, ips, matchType, matchedName, ruleName, clientInfo)
}

// applyIPFiltersInternal uses the Ranger for O(1) checks.
// It expects the lock to be held by the caller.
func (hc *HostsCache) applyIPFiltersInternal(ips []net.IP, qName, ruleName, clientInfo string) []net.IP {
	ranger := hc.ipRanger
	
	// Quick check if ranger is populated? (Insertions > 0)
	// We don't have a count here easily without lock, but we assume it's valid if filterResponses is true.
	
	var kept []net.IP
	for _, ip := range ips {
		networks, err := ranger.ContainingNetworks(ip)
		if err == nil && len(networks) > 0 {
			match := networks[len(networks)-1].Network()
			LogInfo("[HOSTS] FILTERED: Removed IP %s from response for %s | Trigger: %s | Rule: %s | Client: %s", 
				ip.String(), qName, match.String(), ruleName, clientInfo)
			// Dropped
		} else {
			kept = append(kept, ip)
		}
	}
	return kept
}

func (hc *HostsCache) generateRRs(qName string, qType uint16, ips []net.IP, matchType, matchedName, ruleName, clientInfo string) ([]dns.RR, bool) {
	var answers []dns.RR
	ttl := hc.defaultTTL

	for _, ip := range ips {
		if qType == dns.TypeA && ip.To4() != nil {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
			rr.A = ip.To4()
			answers = append(answers, rr)
		} else if qType == dns.TypeAAAA && ip.To4() == nil {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
			rr.AAAA = ip
			answers = append(answers, rr)
		}
	}
	
	if len(answers) > 0 {
		LogInfo("[HOSTS] Resolved: %s (Type: %s) -> %v [Match: %s, Source: %s] | Rule: %s | Client: %s", 
			qName, dns.TypeToString[qType], ips, matchType, matchedName, ruleName, clientInfo)
	} else {
		LogInfo("[HOSTS] No Records: %s found in HOSTS, but no %s records available. | Rule: %s | Client: %s", 
			qName, dns.TypeToString[qType], ruleName, clientInfo)
	}
	return answers, true
}

func (hc *HostsCache) LookupPTR(qName, clientInfo, ruleName string) ([]dns.RR, bool) {
	hc.RLock()
	defer hc.RUnlock()
	ip := extractIPFromPTR(qName)
	if ip == nil {
		return nil, false
	}
	
	if hc.filterResponses {
		contains, err := hc.ipRanger.Contains(ip)
		if err == nil && contains {
			return nil, false
		}
	}

	if isBlockedIP(ip) {
		return nil, true
	}
	names, ok := hc.reverse[ip.String()]
	if !ok {
		return nil, false
	}

	var answers []dns.RR
	ttl := hc.defaultTTL
	for _, name := range names {
		rr := new(dns.PTR)
		rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}
		rr.Ptr = dns.Fqdn(name)
		answers = append(answers, rr)
	}
	LogInfo("[HOSTS] PTR Resolved: %s -> %v | Rule: %s | Client: %s", qName, names, ruleName, clientInfo)
	return answers, true
}

func extractIPFromPTR(qName string) net.IP {
	if strings.HasSuffix(qName, ".in-addr.arpa") {
		parts := strings.Split(strings.TrimSuffix(qName, ".in-addr.arpa"), ".")
		if len(parts) != 4 {
			return nil
		}
		ipStr := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
		return net.ParseIP(ipStr)
	} else if strings.HasSuffix(qName, ".ip6.arpa") {
		hexStr := strings.TrimSuffix(qName, ".ip6.arpa")
		hexStr = strings.ReplaceAll(hexStr, ".", "")
		runes := []rune(hexStr)
		n := len(runes)
		for i := 0; i < n/2; i++ {
			runes[i], runes[n-1-i] = runes[n-1-i], runes[i]
		}
		var sb strings.Builder
		for i, r := range runes {
			if i > 0 && i%4 == 0 {
				sb.WriteString(":")
			}
			sb.WriteRune(r)
		}
		return net.ParseIP(sb.String())
	}
	return nil
}

