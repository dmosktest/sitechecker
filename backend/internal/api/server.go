package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"sitechecker/internal/checks"
	"sitechecker/internal/domain"
	"sitechecker/internal/pow"
	"sitechecker/internal/ssrf"
	"sitechecker/internal/store"
	"sitechecker/internal/verify"
)

type Server struct {
	Store     *store.Store
	PowSecret string
	PowDiff   int
	Mux       *http.ServeMux
}

func New(st *store.Store, powSecret string, powDiff int) *Server {
	s := &Server{Store: st, PowSecret: powSecret, PowDiff: powDiff, Mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.Mux.HandleFunc("GET /health", s.handleHealth)
	s.Mux.HandleFunc("GET /api/v1/pow", s.handlePow)
	s.Mux.HandleFunc("POST /api/v1/checks", s.handleCreateCheck)
	s.Mux.HandleFunc("GET /api/v1/checks/{id}", s.handleGetCheck)
	s.Mux.HandleFunc("GET /api/v1/checks/{id}/report", s.handleGetReport)
	s.Mux.HandleFunc("POST /api/v1/checks/{id}/rescan", s.handleRescanCheck)
	s.Mux.HandleFunc("GET /api/v1/checks/{id}/events", s.handleEvents)
	s.Mux.HandleFunc("POST /api/v1/verifications", s.handleCreateVerification)
	s.Mux.HandleFunc("POST /api/v1/verifications/{id}/confirm", s.handleConfirmVerification)
	s.Mux.HandleFunc("GET /api/v1/verifications", s.handleVerificationStatus)
}

func (s *Server) Handler() http.Handler {
	return withCORS(s.Mux)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code string, retryAfter time.Duration) {
	payload := map[string]any{"error": code}
	if retryAfter > 0 {
		sec := int(retryAfter.Round(time.Second).Seconds())
		if sec < 1 {
			sec = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(sec))
		payload["retry_after"] = sec
	}
	writeJSON(w, status, payload)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handlePow(w http.ResponseWriter, r *http.Request) {
	ch, err := pow.Issue(s.PowSecret, s.PowDiff)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", 0)
		return
	}
	writeJSON(w, http.StatusOK, ch)
}

type createBody struct {
	Domain string `json:"domain"`
	Lang   string `json:"lang"`
	Pow    string `json:"pow"`
	Level  int    `json:"level"`
}

func (s *Server) handleCreateCheck(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_domain", 0)
		return
	}
	var req createBody
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_domain", 0)
		return
	}
	sol, err := pow.DecodeSolution(req.Pow)
	if err != nil || !pow.Verify(s.PowSecret, sol, s.PowDiff) {
		writeErr(w, http.StatusForbidden, "pow_required", 0)
		return
	}
	domainName, err := ssrf.NormalizeDomain(req.Domain)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_domain", 0)
		return
	}
	ip := clientIP(r)
	ctx := r.Context()

	ok, retry, err := s.Store.AllowRate(ctx, "rl:ip:"+ip, 20, time.Hour)
	if err == nil && !ok {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", retry)
		return
	}
	if left, _ := s.Store.DomainCooldownRemaining(ctx, domainName, 30*time.Second); left > 0 {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", left)
		return
	}
	n, _ := s.Store.CountDomainToday(ctx, domainName)
	if n >= 30 {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", s.Store.UntilNextDay())
		return
	}

	if checks.OptedOut(domainName) || checks.CheckSecurityTxtOptOut(ctx, ssrf.NewClient(), domainName) {
		_ = s.Store.Audit(ctx, domainName, ip, "opted_out", nil)
		writeErr(w, http.StatusForbidden, "opted_out", 0)
		return
	}

	if err := ensurePublicTarget(ctx, domainName); err != nil {
		writeErr(w, http.StatusForbidden, "blocked_target", 0)
		return
	}

	level := 1
	if req.Level >= 2 {
		if verify.L2Denied(domainName) {
			writeErr(w, http.StatusForbidden, "verification_required", 0)
			return
		}
		ok, err := s.Store.IsDomainVerified(ctx, domainName)
		if err != nil || !ok {
			writeErr(w, http.StatusForbidden, "verification_required", 0)
			return
		}
		level = 2
	}

	lang := req.Lang
	if lang == "" {
		lang = "ru"
	}
	filesTotal := 1
	if level >= 2 {
		filesTotal = 7
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	rec := &domain.CheckRecord{
		ID: id, Domain: domainName, Lang: lang, State: domain.CheckQueued, Level: level,
		CreatedAt: now,
		Progress: []domain.GroupProgress{
			{ID: domain.GroupHeaders, State: "pending", Total: 8},
			{ID: domain.GroupTLS, State: "pending", Total: 6},
			{ID: domain.GroupCookie, State: "pending", Total: 4},
			{ID: domain.GroupFiles, State: "pending", Total: filesTotal},
			{ID: domain.GroupSoft, State: "pending", Total: 4},
			{ID: domain.GroupDNS, State: "pending", Total: 6},
		},
		Disclaimer: "This report covers passive baseline checks only and does not mean the site is secure.",
	}
	if err := s.Store.CreateCheck(ctx, rec, ip); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", 0)
		return
	}
	job := domain.CheckJob{ID: id, Domain: domainName, Lang: lang, Level: level, CreatedAt: now, IP: ip}
	if err := s.Store.Enqueue(ctx, job); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", 0)
		return
	}
	_ = s.Store.Audit(ctx, domainName, ip, "check_created", map[string]any{"id": id, "level": level})
	writeJSON(w, http.StatusAccepted, map[string]any{"id": id, "level": level})
}

type verifyBody struct {
	Domain string `json:"domain"`
	Method string `json:"method"`
}

func (s *Server) handleCreateVerification(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_domain", 0)
		return
	}
	var req verifyBody
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_domain", 0)
		return
	}
	domainName, err := ssrf.NormalizeDomain(req.Domain)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_domain", 0)
		return
	}
	method := domain.VerifyMethod(strings.ToLower(strings.TrimSpace(req.Method)))
	switch method {
	case domain.VerifyDNS, domain.VerifyFile, domain.VerifyMeta:
	default:
		writeErr(w, http.StatusBadRequest, "invalid_domain", 0)
		return
	}
	if verify.L2Denied(domainName) {
		writeErr(w, http.StatusForbidden, "blocked_target", 0)
		return
	}
	ip := clientIP(r)
	ctx := r.Context()
	ok, retry, err := s.Store.AllowRate(ctx, "rl:verify:"+ip, 30, time.Hour)
	if err == nil && !ok {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", retry)
		return
	}
	token, err := verify.NewToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", 0)
		return
	}
	now := time.Now().UTC()
	v := &domain.Verification{
		ID:           uuid.NewString(),
		Domain:       domainName,
		Method:       method,
		Token:        token,
		Scope:        verify.ScopeFor(method),
		Status:       "pending",
		Instruction:  verify.Instruction(method, domainName, token),
		TokenExpires: now.Add(verify.TokenTTL),
		CreatedAt:    now,
	}
	if err := s.Store.CreateVerification(ctx, v); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", 0)
		return
	}
	_ = s.Store.Audit(ctx, domainName, ip, "verify_started", map[string]string{"id": v.ID, "method": string(method)})
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) handleConfirmVerification(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	v, err := s.Store.GetVerification(ctx, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", 0)
		return
	}
	if time.Now().After(v.TokenExpires) && v.Status != "verified" {
		writeErr(w, http.StatusForbidden, "verification_required", 0)
		return
	}
	if v.Status == "verified" && v.VerifiedUntil != nil && time.Now().Before(*v.VerifiedUntil) {
		writeJSON(w, http.StatusOK, map[string]any{
			"id": v.ID, "domain": v.Domain, "status": "verified", "verified_until": v.VerifiedUntil,
		})
		return
	}
	ip := clientIP(r)
	ok := verify.Confirm(ctx, ssrf.NewClient(), v)
	if !ok {
		_ = s.Store.Audit(ctx, v.Domain, ip, "verify_failed", map[string]string{"id": id, "method": string(v.Method)})
		writeErr(w, http.StatusForbidden, "verification_required", 0)
		return
	}
	until := time.Now().UTC().Add(verify.VerifiedTTL)
	if err := s.Store.MarkVerified(ctx, id, until); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", 0)
		return
	}
	_ = s.Store.Audit(ctx, v.Domain, ip, "verify_ok", map[string]string{"id": id, "method": string(v.Method)})
	writeJSON(w, http.StatusOK, map[string]any{
		"id": id, "domain": v.Domain, "status": "verified", "verified_until": until,
	})
}

func (s *Server) handleVerificationStatus(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("domain")
	domainName, err := ssrf.NormalizeDomain(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_domain", 0)
		return
	}
	ok, until, err := s.Store.VerificationStatus(r.Context(), domainName)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", 0)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"domain": domainName, "verified": ok, "verified_until": until, "l2_denied": verify.L2Denied(domainName),
	})
}

func (s *Server) handleGetCheck(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, err := s.Store.GetCheck(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", 0)
		return
	}
	rec.Findings = nil
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleGetReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, err := s.Store.GetCheck(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", 0)
		return
	}
	if rec.State != domain.CheckDone && rec.State != domain.CheckFailed {
		writeJSON(w, http.StatusAccepted, map[string]any{
			"id": rec.ID, "state": rec.State, "progress": rec.Progress, "fresh": rec.Fresh, "fresh_until": rec.FreshUntil,
		})
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func initialProgress(level int) []domain.GroupProgress {
	filesTotal := 1
	if level >= 2 {
		filesTotal = 7
	}
	return []domain.GroupProgress{
		{ID: domain.GroupHeaders, State: "pending", Total: 8},
		{ID: domain.GroupTLS, State: "pending", Total: 6},
		{ID: domain.GroupCookie, State: "pending", Total: 4},
		{ID: domain.GroupFiles, State: "pending", Total: filesTotal},
		{ID: domain.GroupSoft, State: "pending", Total: 4},
		{ID: domain.GroupDNS, State: "pending", Total: 6},
	}
}

func (s *Server) handleRescanCheck(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	rec, err := s.Store.GetCheck(ctx, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", 0)
		return
	}
	if rec.State == domain.CheckQueued || rec.State == domain.CheckRunning {
		writeJSON(w, http.StatusAccepted, map[string]any{
			"id": rec.ID, "state": rec.State, "progress": rec.Progress, "rescanned": false, "fresh": true,
		})
		return
	}
	if rec.Fresh {
		writeJSON(w, http.StatusOK, map[string]any{
			"id": rec.ID, "state": rec.State, "rescanned": false, "fresh": true, "fresh_until": rec.FreshUntil,
		})
		return
	}

	ip := clientIP(r)
	ok, retry, err := s.Store.AllowRate(ctx, "rl:rescan:"+ip, 20, time.Hour)
	if err == nil && !ok {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", retry)
		return
	}
	if checks.OptedOut(rec.Domain) || checks.CheckSecurityTxtOptOut(ctx, ssrf.NewClient(), rec.Domain) {
		writeErr(w, http.StatusForbidden, "opted_out", 0)
		return
	}
	if err := ensurePublicTarget(ctx, rec.Domain); err != nil {
		writeErr(w, http.StatusForbidden, "blocked_target", 0)
		return
	}

	level := rec.Level
	if level >= 2 {
		if verify.L2Denied(rec.Domain) {
			level = 1
		} else {
			verified, verr := s.Store.IsDomainVerified(ctx, rec.Domain)
			if verr != nil || !verified {
				level = 1
			}
		}
	}
	if level < 1 {
		level = 1
	}

	now := time.Now().UTC()
	rec.Level = level
	rec.State = domain.CheckQueued
	rec.Score = 0
	rec.Grade = ""
	rec.DurationMS = 0
	rec.Findings = nil
	rec.TopFixes = nil
	rec.Error = ""
	rec.FinishedAt = nil
	rec.Progress = initialProgress(level)
	if err := s.Store.ResetCheckForRescan(ctx, rec); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", 0)
		return
	}
	job := domain.CheckJob{ID: rec.ID, Domain: rec.Domain, Lang: rec.Lang, Level: level, CreatedAt: now, IP: ip}
	if err := s.Store.Enqueue(ctx, job); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", 0)
		return
	}
	_ = s.Store.Audit(ctx, rec.Domain, ip, "check_rescanned", map[string]any{"id": rec.ID, "level": level})
	writeJSON(w, http.StatusAccepted, map[string]any{
		"id": rec.ID, "state": domain.CheckQueued, "progress": rec.Progress, "rescanned": true, "fresh": true, "level": level,
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "internal", 0)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	sub := s.Store.SubscribeEvents(r.Context(), id)
	defer sub.Close()
	ch := sub.Channel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			if msg == nil {
				continue
			}
			_, _ = io.WriteString(w, "data: "+msg.Payload+"\n\n")
			flusher.Flush()
		case <-ticker.C:
			rec, err := s.Store.GetCheck(context.Background(), id)
			if err != nil {
				continue
			}
			b, _ := json.Marshal(map[string]any{"type": "status", "state": rec.State, "progress": rec.Progress})
			_, _ = io.WriteString(w, "data: "+string(b)+"\n\n")
			flusher.Flush()
			if rec.State == domain.CheckDone || rec.State == domain.CheckFailed {
				return
			}
		}
	}
}

func ensurePublicTarget(ctx context.Context, domainName string) error {
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupIPAddr(ctx, domainName)
	if err != nil || len(addrs) == 0 {
		return errors.New("blocked_target")
	}
	for _, a := range addrs {
		if ssrf.IsBlockedIP(a.IP) {
			return errors.New("blocked_target")
		}
	}
	return nil
}
