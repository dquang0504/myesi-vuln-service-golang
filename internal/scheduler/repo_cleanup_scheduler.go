package scheduler

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"time"

	"myesi-vuln-service-golang/internal/config"

	"github.com/robfig/cron/v3"
	"go.opentelemetry.io/otel"
)

const repoBaseDir = "/app/tmp/repos"

// cleanUpStaleRepos xoá các thư mục repo trong repoBaseDir
// nếu mtime > retention (ví dụ 7 ngày không đụng tới).
func cleanUpStaleRepos(root string, retention time.Duration) (int, error) {
	now := time.Now()
	deleted := 0

	entries, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[RepoCleanup][WARN] cannot read %s: %v", root, err)
		}
		return 0, nil
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(root, e.Name())
		info, err := os.Stat(path)
		if err != nil {
			log.Printf("[RepoCleanup][WARN] stat %s failed: %v", path, err)
			continue
		}

		age := now.Sub(info.ModTime())
		if age > retention {
			log.Printf("[RepoCleanup] Removing stale repo %s (last modified %s, age=%s)",
				path, info.ModTime().Format(time.RFC3339), age)

			if err := os.RemoveAll(path); err != nil {
				log.Printf("[RepoCleanup][ERR] remove %s failed: %v", path, err)
				continue
			}
			deleted++
		}
	}

	return deleted, nil
}

// StartRepoCleanupScheduler khởi chạy cron job dọn repo cache cũ.
// Sử dụng otel metric tương tự OSV scheduler.
func StartRepoCleanupScheduler() {
	cfg := config.LoadConfig()

	spec := cfg.RepoCleanupSpec
	if spec == "" {
		spec = "@daily"
	}
	retentionDays := cfg.RepoRetentionDays
	if retentionDays <= 0 {
		retentionDays = 7
	}
	retention := time.Duration(retentionDays) * 24 * time.Hour

	meter := otel.Meter("vuln-repo-cleaner")
	runCount, _ := meter.Int64Counter("repo_cleanup.run.count")
	deletedCount, _ := meter.Int64Counter("repo_cleanup.deleted.count")

	c := cron.New(cron.WithSeconds())

	_, err := c.AddFunc(spec, func() {
		start := time.Now()
		ctx := context.Background() // nếu muốn gắn thêm attr sau này

		log.Printf("[RepoCleanup] Start cleanup job — spec=%q, retention=%s", spec, retention)

		n, err := cleanUpStaleRepos(repoBaseDir, retention)
		if err != nil {
			log.Printf("[RepoCleanup][ERR] cleanup failed: %v", err)
		}

		runCount.Add(ctx, 1)
		deletedCount.Add(ctx, int64(n))

		log.Printf("[RepoCleanup] Finished cleanup in %s — deleted=%d",
			time.Since(start), n)
	})
	if err != nil {
		log.Printf("[RepoCleanup] Failed to schedule job: %v", err)
		return
	}

	c.Start()
	log.Printf("[RepoCleanup] scheduler initialized — runs at '%s'", spec)
}
