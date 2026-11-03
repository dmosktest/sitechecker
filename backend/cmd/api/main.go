package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"sitechecker/internal/api"
	"sitechecker/internal/store"
)

func main() {
	ctx := context.Background()
	dbURL := env("DATABASE_URL", "postgres://sitechecker:sitechecker@sitechecker-db:5432/sitechecker?sslmode=disable")
	redisURL := env("REDIS_URL", "redis://sitechecker-redis:6379/0")
	addr := env("HTTP_ADDR", ":8080")
	secret := env("POW_SECRET", "change-me-sitechecker-pow")
	diff, _ := strconv.Atoi(env("POW_DIFFICULTY", "4"))

	st, err := store.Connect(ctx, dbURL, redisURL)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	go func() {
		t := time.NewTicker(6 * time.Hour)
		defer t.Stop()
		for range t.C {
			_ = st.Cleanup(context.Background())
		}
	}()

	srv := api.New(st, secret, diff)
	httpSrv := &http.Server{Addr: addr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}

	go func() {
		log.Printf("sitechecker-api listening on %s", addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
