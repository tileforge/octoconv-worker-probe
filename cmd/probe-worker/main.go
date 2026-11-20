// Command probe-worker serves one approved sanitize capability over Worker Protocol v2.
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tileforge/octoconv-worker-probe/internal/convert"
	"github.com/tileforge/octoconv-worker-probe/internal/sandbox"
)

const sandboxDisabledEnv = "PROBE_SANDBOX_DISABLED"
const probeConcurrencyEnv = "PROBE_WORKER_CONCURRENCY"

func main() {
	if sandbox.RunExecModeIfRequested(os.Args) {
		return
	}
	if err := refuseLegacyStores(); err != nil {
		log.Fatalf("probe protocol: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sandboxHelper, err := sandbox.ResolveHelper(sandboxDisabledEnv)
	if err != nil {
		log.Fatalf("probe sandbox: %v", err)
	}
	probeMaxPages := envInt("PROBE_MAX_PAGES", convert.DefaultProbeMaxPages)
	conv := buildSanitizeConverter(probeMaxPages).WithSandbox(sandboxHelper)
	concurrency := envInt(probeConcurrencyEnv, 1)
	if err := convert.ProbeConcurrencyGuard(conv, concurrency, probeConcurrencyEnv); err != nil {
		log.Fatalf("probe sandbox: %v", err)
	}
	if _, err := probeFreeSlots(); err != nil {
		log.Fatalf("probe protocol: %v", err)
	}
	convert.Default.Replace(conv)
	log.Printf("PROBE_MAX_PAGES=%d", probeMaxPages)
	if len(sandboxHelper) == 0 {
		log.Printf("%s=true: the engines can read every file in this container", sandboxDisabledEnv)
	} else {
		log.Printf("probe sandbox: landlock via %s", strings.Join(sandboxHelper, " "))
	}

	preflightCtx, cancelPreflight := context.WithTimeout(ctx, 60*time.Second)
	if err := convert.ProbePreflight(preflightCtx, conv); err != nil {
		cancelPreflight()
		log.Fatalf("probe sandbox preflight: %v", err)
	}
	cancelPreflight()
	if len(sandboxHelper) > 0 {
		log.Printf("probe sandbox proven: gs, pdfinfo, unzip, and file ran inside the job directory and were denied a file outside every grant")
	}

	dial, err := loadProtocolDial()
	if err != nil {
		log.Fatalf("probe protocol: %v", err)
	}
	log.Printf("probe protocol worker starting")
	if err := runProtocol(ctx, dial); err != nil {
		log.Fatalf("probe protocol: %v", err)
	}
}

func refuseLegacyStores() error {
	if os.Getenv("DATABASE_URL") != "" || os.Getenv("REDIS_ADDR") != "" {
		return errors.New("DATABASE_URL and REDIS_ADDR are not used")
	}
	return nil
}

func probeFreeSlots() (int, error) {
	raw := os.Getenv(probeConcurrencyEnv)
	if raw == "" {
		return 1, nil
	}
	n, err := strconv.Atoi(firstField(raw))
	if err != nil || n != 1 {
		return 0, errors.New("PROBE_WORKER_CONCURRENCY must be 1")
	}
	return 1, nil
}

func buildSanitizeConverter(maxPages int) convert.SanitizeConverter {
	return convert.SanitizeConverter{MaxPages: maxPages}
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(firstField(v)); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(firstField(v)); err == nil {
			return d
		}
	}
	return def
}

func firstField(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			return s[:i]
		}
	}
	return s
}
