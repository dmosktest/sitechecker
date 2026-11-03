package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"sitechecker/internal/domain"
)

const QueueKey = "sitechecker:queue"

type Store struct {
	DB  *pgxpool.Pool
	RDB *redis.Client
}

func Connect(ctx context.Context, databaseURL, redisURL string) (*Store, error) {
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		db.Close()
		return nil, err
	}
	rdb := redis.NewClient(opt)
	if err := rdb.Ping(ctx).Err(); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{DB: db, RDB: rdb}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		rdb.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() {
	if s.DB != nil {
		s.DB.Close()
	}
	if s.RDB != nil {
		_ = s.RDB.Close()
	}
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.DB.Exec(ctx, `
CREATE TABLE IF NOT EXISTS checks (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL,
  lang TEXT NOT NULL DEFAULT 'ru',
  state TEXT NOT NULL,
  level INT NOT NULL DEFAULT 1,
  score INT NOT NULL DEFAULT 0,
  grade TEXT NOT NULL DEFAULT '',
  duration_ms BIGINT NOT NULL DEFAULT 0,
  progress JSONB NOT NULL DEFAULT '[]',
  findings JSONB NOT NULL DEFAULT '[]',
  top_fixes JSONB NOT NULL DEFAULT '[]',
  error TEXT NOT NULL DEFAULT '',
  client_ip TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS checks_expires_idx ON checks (expires_at);
CREATE INDEX IF NOT EXISTS checks_domain_created_idx ON checks (domain, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  domain TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  action TEXT NOT NULL,
  meta JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_log (created_at);
`)
	return err
}

func (s *Store) CreateCheck(ctx context.Context, rec *domain.CheckRecord, ip string) error {
	progress, _ := json.Marshal(rec.Progress)
	findings, _ := json.Marshal(rec.Findings)
	top, _ := json.Marshal(rec.TopFixes)
	expires := time.Now().Add(30 * 24 * time.Hour)
	_, err := s.DB.Exec(ctx, `
INSERT INTO checks (id, domain, lang, state, level, score, grade, duration_ms, progress, findings, top_fixes, error, client_ip, created_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		rec.ID, rec.Domain, rec.Lang, rec.State, rec.Level, rec.Score, rec.Grade, rec.DurationMS,
		progress, findings, top, rec.Error, ip, rec.CreatedAt, expires,
	)
	return err
}

func (s *Store) UpdateCheck(ctx context.Context, rec *domain.CheckRecord) error {
	progress, _ := json.Marshal(rec.Progress)
	findings, _ := json.Marshal(rec.Findings)
	top, _ := json.Marshal(rec.TopFixes)
	_, err := s.DB.Exec(ctx, `
UPDATE checks SET state=$2, score=$3, grade=$4, duration_ms=$5, progress=$6, findings=$7, top_fixes=$8, error=$9, finished_at=$10
WHERE id=$1`,
		rec.ID, rec.State, rec.Score, rec.Grade, rec.DurationMS, progress, findings, top, rec.Error, rec.FinishedAt,
	)
	return err
}

func (s *Store) UpdateProgress(ctx context.Context, id string, state domain.CheckState, progress []domain.GroupProgress) error {
	b, _ := json.Marshal(progress)
	_, err := s.DB.Exec(ctx, `UPDATE checks SET state=$2, progress=$3 WHERE id=$1`, id, state, b)
	return err
}

func (s *Store) GetCheck(ctx context.Context, id string) (*domain.CheckRecord, error) {
	row := s.DB.QueryRow(ctx, `
SELECT id, domain, lang, state, level, score, grade, duration_ms, progress, findings, top_fixes, error, created_at, finished_at
FROM checks WHERE id=$1 AND expires_at > now()`, id)
	var rec domain.CheckRecord
	var progress, findings, top []byte
	var finished *time.Time
	err := row.Scan(&rec.ID, &rec.Domain, &rec.Lang, &rec.State, &rec.Level, &rec.Score, &rec.Grade, &rec.DurationMS,
		&progress, &findings, &top, &rec.Error, &rec.CreatedAt, &finished)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(progress, &rec.Progress)
	_ = json.Unmarshal(findings, &rec.Findings)
	_ = json.Unmarshal(top, &rec.TopFixes)
	rec.FinishedAt = finished
	rec.Disclaimer = "This report covers passive baseline checks only and does not mean the site is secure."
	return &rec, nil
}

func (s *Store) Enqueue(ctx context.Context, job domain.CheckJob) error {
	b, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return s.RDB.LPush(ctx, QueueKey, b).Err()
}

func (s *Store) Dequeue(ctx context.Context, timeout time.Duration) (*domain.CheckJob, error) {
	res, err := s.RDB.BRPop(ctx, timeout, QueueKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}
	if len(res) < 2 {
		return nil, nil
	}
	var job domain.CheckJob
	if err := json.Unmarshal([]byte(res[1]), &job); err != nil {
		return nil, err
	}
	return &job, nil
}

func (s *Store) PublishEvent(ctx context.Context, checkID string, payload any) error {
	b, _ := json.Marshal(payload)
	return s.RDB.Publish(ctx, "sitechecker:events:"+checkID, b).Err()
}

func (s *Store) SubscribeEvents(ctx context.Context, checkID string) *redis.PubSub {
	return s.RDB.Subscribe(ctx, "sitechecker:events:"+checkID)
}

func (s *Store) AllowRate(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	n, err := s.RDB.Incr(ctx, key).Result()
	if err != nil {
		return false, 0, err
	}
	if n == 1 {
		_ = s.RDB.Expire(ctx, key, window).Err()
	}
	if n > int64(limit) {
		ttl, _ := s.RDB.TTL(ctx, key).Result()
		if ttl < 0 {
			ttl = window
		}
		return false, ttl, nil
	}
	return true, 0, nil
}

func (s *Store) DomainCooldownRemaining(ctx context.Context, domain string, within time.Duration) (time.Duration, error) {
	var created time.Time
	since := time.Now().Add(-within)
	err := s.DB.QueryRow(ctx, `
SELECT created_at FROM checks
WHERE domain=$1 AND created_at > $2
ORDER BY created_at DESC
LIMIT 1`, domain, since).Scan(&created)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	left := within - time.Since(created)
	if left < time.Second {
		return 0, nil
	}
	return left, nil
}

func (s *Store) CountDomainToday(ctx context.Context, domain string) (int, error) {
	var n int
	err := s.DB.QueryRow(ctx, `
SELECT COUNT(*) FROM checks WHERE domain=$1 AND created_at > date_trunc('day', now())`, domain).Scan(&n)
	return n, err
}

func (s *Store) UntilNextDay() time.Duration {
	now := time.Now()
	next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
	left := time.Until(next)
	if left < time.Second {
		return time.Second
	}
	return left
}

func (s *Store) Audit(ctx context.Context, domain, ip, action string, meta any) error {
	b, _ := json.Marshal(meta)
	_, err := s.DB.Exec(ctx, `
INSERT INTO audit_log (domain, client_ip, action, meta) VALUES ($1,$2,$3,$4)`,
		domain, ip, action, b)
	return err
}

func (s *Store) Cleanup(ctx context.Context) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM checks WHERE expires_at < now()`)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `DELETE FROM audit_log WHERE created_at < now() - interval '180 days'`)
	return err
}
