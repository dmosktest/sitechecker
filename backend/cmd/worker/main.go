package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sitechecker/internal/checks"
	"sitechecker/internal/domain"
	"sitechecker/internal/score"
	"sitechecker/internal/store"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dbURL := env("DATABASE_URL", "postgres://sitechecker:sitechecker@sitechecker-db:5432/sitechecker?sslmode=disable")
	redisURL := env("REDIS_URL", "redis://sitechecker-redis:6379/0")

	st, err := store.Connect(ctx, dbURL, redisURL)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	runner := checks.NewRunner()
	log.Printf("sitechecker-worker started")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		job, err := st.Dequeue(ctx, 5*time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("dequeue: %v", err)
			time.Sleep(time.Second)
			continue
		}
		if job == nil {
			continue
		}
		process(ctx, st, runner, job)
	}
}

func process(ctx context.Context, st *store.Store, runner *checks.Runner, job *domain.CheckJob) {
	rec, err := st.GetCheck(ctx, job.ID)
	if err != nil {
		log.Printf("get check %s: %v", job.ID, err)
		return
	}
	rec.State = domain.CheckRunning
	_ = st.UpdateProgress(ctx, rec.ID, rec.State, rec.Progress)
	_ = st.PublishEvent(ctx, job.ID, map[string]any{"type": "status", "state": rec.State})

	start := time.Now()
	scanCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	level := job.Level
	if level < 1 {
		level = rec.Level
	}
	if level < 1 {
		level = 1
	}
	findings, progress, err := runner.Run(scanCtx, job.Domain, level, func(evt map[string]any) {
		_ = st.PublishEvent(ctx, job.ID, evt)
		p, ok := evt["progress"].([]domain.GroupProgress)
		if !ok {
			return
		}
		cp := append([]domain.GroupProgress(nil), p...)
		rec.Progress = cp
		_ = st.UpdateProgress(ctx, rec.ID, domain.CheckRunning, cp)
	})
	finished := time.Now().UTC()
	rec.FinishedAt = &finished
	rec.DurationMS = time.Since(start).Milliseconds()
	rec.Progress = progress

	if err != nil {
		rec.State = domain.CheckFailed
		rec.Error = err.Error()
		if rec.Error == "blocked_target" || rec.Error == "invalid_domain" {
			rec.Error = err.Error()
		}
		_ = st.UpdateCheck(ctx, rec)
		_ = st.PublishEvent(ctx, job.ID, map[string]any{"type": "status", "state": rec.State, "error": rec.Error})
		return
	}

	sc, grade, top := score.Compute(findings)
	rec.Findings = findings
	rec.Score = sc
	rec.Grade = grade
	rec.TopFixes = top
	rec.State = domain.CheckDone
	_ = st.UpdateCheck(ctx, rec)
	_ = st.PublishEvent(ctx, job.ID, map[string]any{"type": "done", "score": sc, "grade": grade})
	log.Printf("check %s domain=%s grade=%s score=%d in %dms", job.ID, job.Domain, grade, sc, rec.DurationMS)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
