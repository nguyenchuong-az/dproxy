/*
File: process.go
Version: 3.10.0
Last Update: 2026-01-11
Description: Handles the core processing logic for DNS requests.
             UPDATED: Applied Dynamic Rate Limiting at the start of request processing.
             UPDATED: Applied LogClientName logic for rich logging.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// Serve Stale Configuration
const (
	StaleGracePeriod = 24 * time.Hour // How long to serve stale data after expiry
	StaleTTL         = 5              // TTL to serve for stale records (seconds)
)

type queryResult struct {
	msg         *dns.Msg
	upstreamStr string
	rtt         time.Duration
	upstreamQID uint16 // Store the ID used for upstream
}

func processDNSRequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, reqCtxFromHandler *RequestContext) {
	// --- PANIC RECOVERY ---
	defer func() {
		if rec := recover(); rec != nil {
			LogError("Panic in processDNSRequest: %v\nStack: %s", rec, debug.Stack())
			dns.HandleFailed(w, r)
		}
	}()

	start := time.Now()
	
	// --- 0. DYNAMIC RATE LIMITING ---
	// Checked before parsing detailed context to save resources on overload
	remoteAddr := w.RemoteAddr()
	clientIP := getIPFromAddr(remoteAddr)
	
	action, delay, reason := GlobalLimiter.Check(clientIP)
	
	if action == ActionDrop {
		LogWarn("[LIMIT] DROPPED request from %s | Reason: %s", clientIP, reason)
		return 
	}
	
	if action == ActionDelay {
		if delay > 0 {
			LogInfo("[LIMIT] DELAYING request from %s by %v | Reason: %s", clientIP, delay, reason)
			select {
			case <-time.After(delay):
				// Continue processing
			case <-ctx.Done():
				return // Client gave up
			}
		}
	}

	// Capture the original QID from the client.
	originalID := r.Id

	reqCtx := reqCtxPool.Get().(*RequestContext)
	reqCtx.Reset()
	defer reqCtxPool.Put(reqCtx)

	reqCtx.ServerIP = reqCtxFromHandler.ServerIP
	reqCtx.ServerPort = reqCtxFromHandler.ServerPort
	reqCtx.Protocol = reqCtxFromHandler.Protocol
	reqCtx.ServerHostname = reqCtxFromHandler.ServerHostname
	reqCtx.ServerPath = reqCtxFromHandler.ServerPath

	var mac net.HardwareAddr
	if IsValidARPCandidate(clientIP) {
		mac = getMacFromCache(clientIP)
	}

	reqCtx.ClientIP = clientIP
	reqCtx.ClientMAC = mac

	extractEDNS0ClientInfo(r, reqCtx)

	var qInfo, cacheKey string
	var qType uint16
	var sb strings.Builder

	if len(r.Question) > 0 {
		q := r.Question[0]
		reqCtx.QueryName = strings.TrimSuffix(strings.ToLower(q.Name), ".")
		qType = q.Qtype
		qInfo = buildQueryInfo(q)
	}

	// Only build log string if necessary
	if IsInfoEnabled() {
		sb.Reset()
		qInfo = appendEDNSInfoToLog(&sb, reqCtx, qInfo, r)
		sb.Reset()
	}

	if config.Server.DDR.Enabled && qType == dns.TypeSVCB && reqCtx.QueryName == "_dns.resolver.arpa" {
		if resp := generateDDRResponse(r, reqCtx.ServerIP); resp != nil {
			// Ensure response ID matches request ID
			resp.Id = originalID
			w.WriteMsg(resp)
			if IsInfoEnabled() {
				logRequest(originalID, 0, reqCtx, "DDR", qInfo, "", "NOERROR (DDR)", "INTERNAL", 0, time.Since(start), resp)
			}
			return
		}
	}

	selectedUpstreams, selectedStrategy, ruleName, hostsCache, hostsWildcard := SelectUpstreams(reqCtx)

	if len(r.Question) > 0 {
		q := r.Question[0]
		routingKey := ruleName
		
		// OPTIMIZATION: Efficient cache key generation
		sb.Reset()
		sb.WriteString(reqCtx.QueryName)
		sb.WriteString("|")
		sb.WriteString(strconv.Itoa(int(q.Qtype)))
		sb.WriteString("|")
		sb.WriteString(strconv.Itoa(int(q.Qclass)))
		sb.WriteString("|")
		sb.WriteString(routingKey)
		cacheKey = sb.String()
	}

	// --- CACHE CHECK (First) ---
	if config.Cache.Enabled && cacheKey != "" {
		if cachedResp, remainingTTL := getFromCacheWithTTL(cacheKey, originalID); cachedResp != nil {
			// Hit! Serve immediately.
			serveCache(w, cachedResp, remainingTTL, originalID, reqCtx, ruleName, qInfo, start)
			return // Exit prevents any cross-fetching logic below
		}
	}

	// --- HOSTS FILE CHECK (Second) ---
	if hostsCache != nil && len(r.Question) > 0 {
		var answers []dns.RR
		var found bool

		clientInfo := reqCtx.ClientIP.String()
		if reqCtx.ClientMAC != nil {
			clientInfo = fmt.Sprintf("%s (%s)", clientInfo, reqCtx.ClientMAC.String())
		}

		if qType == dns.TypePTR {
			answers, found = hostsCache.LookupPTR(reqCtx.QueryName, clientInfo, ruleName)
		} else {
			answers, found = hostsCache.Lookup(reqCtx.QueryName, qType, hostsWildcard, clientInfo, ruleName)
		}

		if found {
			resp := new(dns.Msg)
			resp.SetReply(r)
			resp.Id = originalID // Ensure ID matches

			if config.Server.Response.CNAMEFlattening {
				flattenCNAMEs(resp)
			}
			applyTTLClamping(resp)
			applyTTLStrategy(resp)
			sortResponse(resp)

			if len(answers) > 0 {
				resp.Answer = answers

				if config.Cache.Enabled && cacheKey != "" {
					addToCache(cacheKey, resp)
				}

				w.WriteMsg(resp)
				if IsInfoEnabled() {
					logRequest(originalID, 0, reqCtx, ruleName, qInfo, "", "NOERROR (HOSTS)", "HOSTS", 0, time.Since(start), resp)
				}
			} else {
				resp.Rcode = dns.RcodeNameError

				if config.Cache.Enabled && cacheKey != "" {
					addToCache(cacheKey, resp)
				}

				w.WriteMsg(resp)
				if IsInfoEnabled() {
					logRequest(originalID, 0, reqCtx, ruleName, qInfo, "", "NXDOMAIN (HOSTS)", "HOSTS", 0, time.Since(start), resp)
				}
			}
			return
		}
	}

	// --- HARDEN BELOW NXDOMAIN CHECK (Third) ---
	if config.Cache.Enabled && config.Cache.HardenBelowNXDOMAIN && len(r.Question) > 0 {
		checkName := dns.Fqdn(reqCtx.QueryName)
		isNX, remainingTTL := CheckParentNXDomain(checkName, ruleName)
		
		if IsDebugEnabled() {
			typeName := "UNKNOWN"
			if t, ok := dns.TypeToString[qType]; ok {
				typeName = t
			} else {
				typeName = strconv.Itoa(int(qType))
			}
			LogDebug("[PROCESS] HardenNX Check: %s (%s) (Rule: %s) -> Hit: %v", checkName, typeName, ruleName, isNX)
		}

		if isNX {
			LogDebug("[PROCESS] HardenNX triggered for %s (Rule: %s)", checkName, ruleName)

			resp := new(dns.Msg)
			resp.SetReply(r)
			resp.Id = originalID // Ensure ID matches
			resp.Rcode = dns.RcodeNameError
			
			w.WriteMsg(resp)
			if IsInfoEnabled() {
				status := fmt.Sprintf("NXDOMAIN (HARDENED, TTL:%ds)", remainingTTL)
				logRequest(originalID, 0, reqCtx, ruleName, qInfo, "", status, "CACHE", 0, time.Since(start), resp)
			}
			return
		}
	}

	// --- UPSTREAM FORWARDING ---

	msg := r.Copy()
	// IMPORTANT: Randomize the QID for the upstream query.
	randomID := dns.Id()
	msg.Id = randomID
	
	addEDNS0Options(msg, clientIP, mac)

	upstreamQInfo := ""
	if IsDebugEnabled() || IsInfoEnabled() {
		upstreamQInfo = buildUpstreamInfo(msg)
	}

	if IsDebugEnabled() {
		logEDNSDebug(msg, originalID)
	}

	// --- Singleflight Optimization ---

	safeReqCtx := reqCtx.Clone()

	// Use cacheKey as the suppression key
	ch := requestGroup.DoChan(cacheKey, func() (interface{}, error) {
		// STANDARD UPSTREAM FORWARDING
		upstreamTimeout := getTimeout()
		if upstreamTimeout == 0 {
			upstreamTimeout = 5 * time.Second
		}
		uCtx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
		defer cancel()

		resp, upstreamStr, rtt, err := forwardToUpstreams(uCtx, msg, selectedUpstreams, selectedStrategy, ruleName, safeReqCtx)
		if err != nil {
			return nil, err
		}
		// Return the randomized ID used alongside the result
		return queryResult{msg: resp, upstreamStr: upstreamStr, rtt: rtt, upstreamQID: randomID}, nil
	})

	var result singleflight.Result

	select {
	case <-ctx.Done():
		LogDebug("Query %s cancelled or timed out while waiting for singleflight", qInfo)
		return
	case res := <-ch:
		result = res
	}

	if result.Err != nil {
		if errors.Is(result.Err, context.DeadlineExceeded) || errors.Is(result.Err, context.Canceled) {
			LogWarn("Query timeout for %s from %s", qInfo, clientIP)
		} else {
			LogError("Error resolving %s from %s: %v", qInfo, clientIP, result.Err)
		}

		if config.Server.DropOnFailure {
			LogDebug("[PROCESS] Dropping query %s due to failure (drop_on_failure=true).", qInfo)
		} else {
			dns.HandleFailed(w, r)
		}
		return
	}

	qr := result.Val.(queryResult)
	resp := qr.msg
	shared := result.Shared
	// If shared, qr.upstreamQID might be from the other request that won the race.
	// For logging purposes, we should ideally log the ID that *this* request would have used (randomID),
	// or the one that actually went out. Since singleflight coalesces, only one went out.
	// Let's use the one from the result.
	actualUpstreamQID := qr.upstreamQID

	if shared && resp != nil {
		resp = resp.Copy()
	}

	if resp != nil {
		// --- IP FILTERING ON UPSTREAM RESPONSE ---
		if hostsCache != nil {
			clientInfo := reqCtx.ClientIP.String()
			if reqCtx.ClientMAC != nil {
				clientInfo = fmt.Sprintf("%s (%s)", clientInfo, reqCtx.ClientMAC.String())
			}
			
			// Filter IPs. If returns true, message was modified.
			hostsCache.FilterResponse(resp, reqCtx.QueryName, ruleName, clientInfo)
		}

		cleanResponse(resp)
		if config.Server.Response.CNAMEFlattening {
			flattenCNAMEs(resp)
		}
		applyTTLClamping(resp)
		applyTTLStrategy(resp)
		sortResponse(resp)
	}

	if config.Cache.Enabled && resp != nil {
		addToCache(cacheKey, resp)

		if config.Cache.Prefetch.CrossFetch.Enabled && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			mode := config.Cache.Prefetch.CrossFetch.Mode
			shouldPrefetch := false

			switch mode {
			case "on_a":
				shouldPrefetch = (qType == dns.TypeA)
			case "on_aaaa":
				shouldPrefetch = (qType == dns.TypeAAAA)
			case "both":
				shouldPrefetch = (qType == dns.TypeA || qType == dns.TypeAAAA)
			}

			if shouldPrefetch {
				req := prefetchReq{
					qName:      reqCtx.QueryName,
					qType:      qType,
					routingKey: ruleName,
					upstreams:  selectedUpstreams,
					strategy:   selectedStrategy,
					clientIP:   reqCtx.ClientIP,
					clientMAC:  reqCtx.ClientMAC,
				}
				AttemptCrossFetch(req)
			}
		}
	}

	status := dns.RcodeToString[resp.Rcode]
	if shared {
		status = fmt.Sprintf("%s (COALESCED)", status)
	}

	// CRITICAL: Restore the original Client's ID before sending back.
	resp.Id = originalID

	w.WriteMsg(resp)

	if IsInfoEnabled() {
		logRequest(originalID, actualUpstreamQID, reqCtx, ruleName, qInfo, upstreamQInfo, status, qr.upstreamStr, qr.rtt, time.Since(start), resp)
	}
}

func serveCache(w dns.ResponseWriter, resp *dns.Msg, ttl uint32, id uint16, reqCtx *RequestContext, ruleName, qInfo string, start time.Time) {
	resp.Id = id
	w.WriteMsg(resp)

	if IsInfoEnabled() {
		isNegative := resp.Rcode == dns.RcodeNameError || len(resp.Answer) == 0
		var status string
		if isNegative {
			status = fmt.Sprintf("CACHE_HIT (NEG, TTL:%ds)", ttl)
		} else {
			status = fmt.Sprintf("CACHE_HIT (TTL:%ds)", ttl)
		}
		logRequest(id, 0, reqCtx, ruleName, qInfo, "", status, "CACHE", 0, time.Since(start), resp)
	}
}

func logRequest(clientQID, upstreamQID uint16, reqCtx *RequestContext, ruleName, qInfo, upstreamQInfo, status, upstream string, upstreamRTT, duration time.Duration, resp *dns.Msg) {
	macStr := "N/A"
	if reqCtx.ClientMAC != nil {
		macStr = reqCtx.ClientMAC.String()
	}

	// IMPLEMENTED: LogClientName support (Resolve IP to Name)
	clientIdentity := reqCtx.ClientIP.String()
	if config.Logging.LogClientName {
		// 1. Try internal hosts cache (Default Rule has the most global view usually)
		var names []string
		if defHosts := config.Routing.DefaultRule.parsedHosts; defHosts != nil {
			names = defHosts.GetHostnames(reqCtx.ClientIP)
		}
		
		if len(names) > 0 {
			// Found in local hosts file/cache
			clientIdentity = fmt.Sprintf("%s (%s)", clientIdentity, names[0])
		} else {
			// 2. Fallback to System Resolver (DNS)
			// NOTE: This can be blocking, but since we are in the log handler which is usually async or post-response, it's acceptable.
			if names, err := net.LookupAddr(reqCtx.ClientIP.String()); err == nil && len(names) > 0 {
				clientIdentity = fmt.Sprintf("%s (%s)", clientIdentity, strings.TrimSuffix(names[0], "."))
			}
		}
	}

	var sb strings.Builder
	sb.WriteString(reqCtx.ServerIP.String())
	sb.WriteString(":")
	sb.WriteString(strconv.Itoa(reqCtx.ServerPort))
	if reqCtx.ServerHostname != "" {
		sb.WriteString(" | Host:")
		sb.WriteString(reqCtx.ServerHostname)
	}
	if reqCtx.ServerPath != "" {
		sb.WriteString(" | Path:")
		sb.WriteString(reqCtx.ServerPath)
	}
	ingress := sb.String()

	LogInfo("[QRY] QID:%d | Rule:%s | Client:%s | MAC:%s | Proto:%s | Ingress:%s | Query:%s",
		clientQID, ruleName, clientIdentity, macStr, reqCtx.Protocol, ingress, qInfo)

	if upstream != "" && upstream != "CACHE" {
		useInfo := qInfo
		if upstreamQInfo != "" {
			useInfo = upstreamQInfo
		}
		
		// If randomized, mark with *
		qidStr := fmt.Sprintf("%d", upstreamQID)
		if upstreamQID != clientQID {
			qidStr += "*"
		}

		LogInfo("[FWD] QID:%s | Rule:%s | Upstream:%s | RTT:%v | Query:%s | Response:%s", qidStr, ruleName, upstream, upstreamRTT, useInfo, status)
	}

	sb.Reset()
	if resp != nil {
		first := true
		addRRs := func(rrs []dns.RR) {
			for _, rr := range rrs {
				if _, ok := rr.(*dns.OPT); ok {
					continue
				}
				parts := strings.Fields(rr.String())
				if len(parts) >= 4 {
					if !first {
						sb.WriteString(", ")
					}
					sb.WriteString(parts[3])
					if len(parts) > 4 {
						sb.WriteString(" ")
						sb.WriteString(strings.Join(parts[4:], " "))
					}
					first = false
				}
			}
		}
		addRRs(resp.Answer)
		addRRs(resp.Ns)
		addRRs(resp.Extra)
	}

	ansStr := sb.String()
	if ansStr == "" {
		ansStr = "Empty"
	}

	// Response log uses Client QID again to close the loop
	// Added Client:%s matching the QRY format
	LogInfo("[RSP] QID:%d | Client:%s | Status:%s | TotalTime:%v | Query:%s | Answers:[%s]", clientQID, clientIdentity, status, duration, qInfo, ansStr)
}

