package utils

import (
	"context"
	"fmt"
	rds "myesi-vuln-service-golang/internal/redis"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis Key helpers
func scanRunningKey(orgID int, ctx context.Context) string {
	return fmt.Sprintf("scan_running:%d", orgID)
}

func scanLockKey(orgID int, ctx context.Context) string {
	return fmt.Sprintf("scan_lock:%d", orgID)
}

// Attempts to acquire a lock for this org (prevent race conditions)
func AcquireScanLock(orgID int, ctx context.Context) (bool, error) {
	return rds.Client.SetNX(ctx, scanLockKey(orgID, ctx), 1, 5*time.Second).Result()
}

func ReleaseScanLock(orgID int, ctx context.Context) {
	rds.Client.Del(ctx, scanLockKey(orgID, ctx))
}

// Increase the running scan counter
func IncrementRunning(orgID int, ctx context.Context) {
	rds.Client.Incr(ctx, scanRunningKey(orgID, ctx))
}

// Decrease after scan completes
func DecrementRunning(orgID int, ctx context.Context) {
	rds.Client.Decr(ctx, scanRunningKey(orgID, ctx))
}

// Get current running scan count
func GetRunningCount(orgID int, ctx context.Context) (int, error) {
	cnt, err := rds.Client.Get(ctx, scanRunningKey(orgID, ctx)).Int()
	if err == redis.Nil {
		return 0, nil
	}
	return cnt, err
}
