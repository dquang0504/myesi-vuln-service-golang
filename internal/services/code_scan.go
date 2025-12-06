package services

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"myesi-vuln-service-golang/internal/config"
	"myesi-vuln-service-golang/internal/db"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/robfig/cron/v3"
	"github.com/segmentio/kafka-go"
)

var supportedManifests = map[string]struct{}{
	"package-lock.json": {},
	"yarn.lock":         {},
	"pnpm-lock.yaml":    {},
	"go.mod":            {},
	"requirements.txt":  {},
	"pyproject.toml":    {},
	"pom.xml":           {},
	"build.gradle":      {},
	"Cargo.toml":        {},
	"Gemfile":           {},
	"composer.json":     {},
	"composer.lock":     {},
}

type Manifest struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Content string `json:"content"` // text content
	Size    int    `json:"size"`    // bytes
}

// CodeScanRequest defines payload for API trigger
type CodeScanRequest struct {
	ProjectName    string `json:"project_name"`
	RepoURL        string `json:"repo_url,omitempty"`
	Tool           string `json:"tool"`         // semgrep | bandit
	GithubToken    string `json:"github_token"` // optional — prefer user token
	OrganizationID int    `json:"organization_id"`
	UserID         int    `json:"user_id,omitempty"` // used to invalidate bad GitHub token
}

// ==== Repo cache config =====================================================

const repoBaseDir = "/app/tmp/repos"

// getDefaultBranch tries to read github_default_branch from DB, fallback "main"
func getDefaultBranch(ctx context.Context, projectID int, projectName string) string {
	branch := "main"
	err := db.Conn.QueryRowContext(ctx,
		"SELECT COALESCE(NULLIF(github_default_branch, ''), 'main') FROM projects WHERE id = $1",
		projectID,
	).Scan(&branch)
	if err != nil {
		log.Printf("[SCAN][WARN] cannot determine default branch for %s (id=%d), using 'main': %v", projectName, projectID, err)
		branch = "main"
	}
	return branch
}

func gitCloneRepo(ctx context.Context, cloneURL, dir, branch string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return fmt.Errorf("mkdir base dir: %w", err)
	}

	args := []string{"clone", "--depth=1"}
	if branch != "" {
		args = append(args, "--branch", branch, "--single-branch")
	}
	args = append(args, cloneURL, dir)

	cmd := exec.CommandContext(ctx, "git", args...)
	var buf bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &buf)

	log.Printf("[SCAN] git %v", args)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start git clone: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			_ = cmd.Process.Kill()
			return fmt.Errorf("git clone timeout: %w", ctx.Err())
		}
		return fmt.Errorf("git clone failed: %w, output: %s", err, buf.String())
	}
	return nil
}

func gitUpdateRepo(ctx context.Context, dir, branch string) error {
	// ensure still a git repo
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return fmt.Errorf("not a git repo: %w", err)
	}

	// git -C dir fetch origin
	cmdFetch := exec.CommandContext(ctx, "git", "-C", dir, "fetch", "origin")
	var outFetch bytes.Buffer
	cmdFetch.Stdout = &outFetch
	cmdFetch.Stderr = &outFetch
	if err := cmdFetch.Run(); err != nil {
		return fmt.Errorf("git fetch failed: %v\n%s", err, outFetch.String())
	}

	// git -C dir checkout <branch>
	cmdCheckout := exec.CommandContext(ctx, "git", "-C", dir, "checkout", branch)
	var outCheckout bytes.Buffer
	cmdCheckout.Stdout = &outCheckout
	cmdCheckout.Stderr = &outCheckout
	if err := cmdCheckout.Run(); err != nil {
		return fmt.Errorf("git checkout %s failed: %v\n%s", branch, err, outCheckout.String())
	}

	// git -C dir reset --hard origin/<branch>
	cmdReset := exec.CommandContext(ctx, "git", "-C", dir, "reset", "--hard", "origin/"+branch)
	var outReset bytes.Buffer
	cmdReset.Stdout = &outReset
	cmdReset.Stderr = &outReset
	if err := cmdReset.Run(); err != nil {
		return fmt.Errorf("git reset --hard origin/%s failed: %v\n%s", branch, err, outReset.String())
	}

	return nil
}

func touchRepoDir(dir string) {
	now := time.Now()
	if err := os.Chtimes(dir, now, now); err != nil {
		log.Printf("[SCAN][WARN] update mtime for %s failed: %v", dir, err)
	}
}

// prepareRepo ensures we have a fresh working copy of the repo local path:
//
// - Use projectID as folder name: /app/tmp/repos/<projectID>
// - If not available: git clone --depth=1
// - If repo is available: git fetch + checkout + reset --hard origin/<branch>
// - If pull failed: delete folder & clone again
func prepareRepo(ctx context.Context, projectID int, projectName, repoURL, githubToken string) (string, error) {
	if repoURL == "" {
		return "", fmt.Errorf("repoURL is empty for project %s", projectName)
	}

	dir := filepath.Join(repoBaseDir, fmt.Sprintf("%d", projectID))

	// sanitize repo url to avoid hidden chars
	repoURL = sanitizeURL(repoURL)

	// input token if is GitHub HTTPS
	cloneURL := repoURL
	if githubToken != "" && strings.Contains(repoURL, "github.com") && strings.HasPrefix(repoURL, "https://") {
		cloneURL = strings.Replace(repoURL, "https://", "https://"+strings.TrimSpace(githubToken)+"@", 1)
	}

	branch := getDefaultBranch(ctx, projectID, projectName)

	// chưa có thư mục → clone mới
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		log.Printf("[SCAN] No local repo for %s (id=%d), cloning into %s", projectName, projectID, dir)
		if err := gitCloneRepo(ctx, cloneURL, dir, branch); err != nil {
			return "", err
		}
		touchRepoDir(dir)
		return dir, nil
	}

	// có thư mục nhưng không phải git repo → xoá rồi clone lại
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		log.Printf("[SCAN][WARN] %s exists but is not a git repo, recreating", dir)
		_ = os.RemoveAll(dir)
		if err := gitCloneRepo(ctx, cloneURL, dir, branch); err != nil {
			return "", err
		}
		touchRepoDir(dir)
		return dir, nil
	}

	// repo đã tồn tại → cập nhật
	log.Printf("[SCAN] Reusing cached repo at %s, syncing branch %s", dir, branch)
	if err := gitUpdateRepo(ctx, dir, branch); err != nil {
		log.Printf("[SCAN][WARN] git update failed for %s, recloning: %v", projectName, err)
		_ = os.RemoveAll(dir)
		if err2 := gitCloneRepo(ctx, cloneURL, dir, branch); err2 != nil {
			return "", fmt.Errorf("reclone after failed update: %v (original: %v)", err2, err)
		}
	}
	touchRepoDir(dir)

	return dir, nil
}

func sanitizeURL(s string) string {
	s = strings.TrimSpace(s)
	// remove zero-width and control-like chars that break git auth
	clean := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		// invisible format chars (Cf)
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	return clean
}

// resolveGithubToken picks the best available token: explicit > user token in DB > env GITHUB_TOKEN.
func resolveGithubToken(ctx context.Context, token string, userID int) string {
	if token = strings.TrimSpace(token); token != "" {
		return token
	}

	// lookup user token from DB
	if userID > 0 {
		var userToken sql.NullString
		err := db.Conn.QueryRowContext(ctx, "SELECT github_token FROM users WHERE id=$1", userID).Scan(&userToken)
		if err == nil && userToken.Valid && strings.TrimSpace(userToken.String) != "" {
			return strings.TrimSpace(userToken.String)
		}
	}

	// fallback env
	if envToken := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); envToken != "" {
		return envToken
	}

	return ""
}

// RunCodeScan executes Semgrep or Bandit and sends event to Kafka
func RunCodeScan(projectName, repoURL, tool, githubToken string, userID int) error {
	start := time.Now()
	log.Printf("[SCAN] Starting code scan for %s using %s", projectName, tool)

	ctx := context.Background()

	// Lấy projectID để:
	// 1) Làm thư mục cache ổn định
	// 2) Đẩy vào event Kafka mà không cần query lại
	var projectID int
	if err := db.Conn.QueryRowContext(ctx,
		"SELECT id FROM projects WHERE name = $1",
		projectName,
	).Scan(&projectID); err != nil {
		log.Printf("[SCAN][ERR] project lookup failed for %s: %v", projectName, err)
		return err
	}

	// Resolve GitHub token: prefer provided, else user token, else env.
	githubToken = resolveGithubToken(ctx, githubToken, userID)

	findings, manifests, err := ExecuteScanner(tool, repoURL, githubToken, projectName, projectID, userID)
	if err != nil {
		log.Printf("[SCAN][ERR] %v", err)
		return err
	}

	// Save to DB
	SaveCodeFindings(projectID, projectName, findings)

	// Publish Kafka event (with manifests)
	err = PublishCodeScanEvent(projectID, projectName, findings, manifests)
	if err != nil {
		log.Printf("[SCAN][ERR] publish error: %v", err)
		return err
	}

	log.Printf("[SCAN] Finished code scan for %s (%d findings, %v)",
		projectName, len(findings), time.Since(start))

	return nil
}

// ExecuteScanner runs semgrep or bandit and returns findings + discovered manifests
func ExecuteScanner(tool, target, githubToken, projectName string, projectID int, userID int) ([]map[string]interface{}, []Manifest, error) {
	if tool != "semgrep" && tool != "bandit" {
		return nil, nil, fmt.Errorf("unsupported tool: %s", tool)
	}

	// === Chuẩn bị repo local (clone lần đầu / pull các lần sau) ===
	log.Printf("[SCAN] Repo URL: %s", target)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	dir, err := prepareRepo(ctx, projectID, projectName, target, githubToken)
	if err != nil {
		log.Printf("[SCAN][ERR] prepareRepo failed: %v", err)
		// If auth failure, clear stored GitHub token to force reconnect
		if userID > 0 {
			lower := strings.ToLower(err.Error())
			if strings.Contains(lower, "could not read password") || strings.Contains(lower, "authentication") {
				if _, dbErr := db.Conn.ExecContext(ctx, "UPDATE users SET github_token = NULL WHERE id = $1", userID); dbErr != nil {
					log.Printf("[SCAN][WARN] failed to clear github_token for user %d: %v", userID, dbErr)
				} else {
					log.Printf("[SCAN][INFO] Cleared github_token for user %d due to auth failure", userID)
				}
			}
		}
		return nil, nil, err
	}
	log.Printf("[SCAN] Using repo at %s", dir)

	// === Detect manifest files ===
	var manifests []Manifest
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := filepath.Base(path)
		if _, ok := supportedManifests[name]; ok {
			const maxBytes = 10024 * 1024
			data, err := os.ReadFile(path)
			if err != nil {
				log.Printf("[SCAN][WARN] failed to read manifest %s: %v", path, err)
				return nil
			}
			if len(data) > maxBytes {
				data = data[:maxBytes]
				data = append(data, []byte("\n/* TRUNCATED */")...)
			}
			manifests = append(manifests, Manifest{
				Path:    strings.TrimPrefix(path, dir+"/"),
				Name:    name,
				Content: string(data),
				Size:    len(data),
			})
		}
		return nil
	})

	// === Get languages from DB ===
	var langJSON []byte
	err = db.Conn.QueryRowContext(ctx,
		"SELECT github_language FROM projects WHERE id = $1",
		projectID,
	).Scan(&langJSON)
	if err != nil {
		log.Printf("[SCAN][WARN] cannot fetch languages for project %s (id=%d): %v", projectName, projectID, err)
		langJSON = []byte("[]")
	}

	langs := []string{}
	if len(langJSON) > 0 {
		if err := json.Unmarshal(langJSON, &langs); err != nil {
			log.Printf("[SCAN][WARN] invalid github_language JSON for %s: %v", projectName, err)
		}
	}
	if len(langs) == 0 {
		log.Printf("[SCAN][WARN] No languages found for project %s — defaulting to auto", projectName)
		langs = append(langs, "auto")
	}

	// === Resolve Semgrep configs ===
	configs := config.ResolveSemgrepConfigs(langs)
	log.Printf("[SCAN] Selected Semgrep configs for %s: %v", projectName, configs)

	// === Build scanner command ===
	var out bytes.Buffer
	cmdArgs := []string{}

	if tool == "semgrep" {
		cmdArgs = append(cmdArgs, "scan")
		// if semgrep accepts multiple --config flags, pass them
		for _, cfg := range configs {
			cmdArgs = append(cmdArgs, "--config", cfg)
		}
		// keep a sensible default set of flags
		cmdArgs = append(cmdArgs,
			"--json",
			"--quiet",
			"--disable-version-check",
			dir,
		)
	} else if tool == "bandit" {
		cmdArgs = []string{"-r", dir, "-f", "json"}
	}

	scanCtx, scanCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer scanCancel()

	scanCmd := exec.CommandContext(scanCtx, tool, cmdArgs...)
	scanCmd.Stdout = &out
	scanCmd.Stderr = &out
	if err := scanCmd.Run(); err != nil {
		if strings.Contains(out.String(), "HTTP 404") {
			log.Printf("[SCAN][WARN] Some configs not found (404), continuing partial scan...")
		} else {
			log.Printf("[SCAN][ERR] %s run failed: %v\n%s", tool, err, out.String())
		}
	}

	raw := out.String()

	// === Parse JSON results ===
	var findings []map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &findings); err != nil {
		var wrapper map[string]interface{}
		if err2 := json.Unmarshal([]byte(raw), &wrapper); err2 == nil {
			if results, ok := wrapper["results"].([]interface{}); ok {
				for _, r := range results {
					if m, ok := r.(map[string]interface{}); ok {
						findings = append(findings, m)
					}
				}
			}
		} else {
			log.Printf("[SCAN][WARN] could not parse JSON output from %s: %v", tool, err2)
			if len(raw) > 0 {
				snippet := raw
				if len(snippet) > 500 {
					snippet = snippet[:500]
				}
				log.Printf("[SCAN][WARN] output snippet:\n%s", snippet)
			}
		}
	}

	return findings, manifests, nil
}

func PublishCodeScanEvent(projectID int, projectName string, findings []map[string]interface{}, manifests []Manifest) error {
	cfg := config.LoadConfig()
	w := kafka.Writer{
		Addr:  kafka.TCP(strings.Split(cfg.KafkaBroker, ",")...),
		Topic: "code-scan-results",
	}
	defer w.Close()

	event := map[string]interface{}{
		"event_type": "CODE_SCAN_DONE",
		"project":    projectName,
		"project_id": projectID,
		"findings":   findings,
		"timestamp":  time.Now(),
	}

	if len(manifests) > 0 {
		eventManifests := []map[string]interface{}{}
		for _, m := range manifests {
			eventManifests = append(eventManifests, map[string]interface{}{
				"name":    m.Name,
				"path":    m.Path,
				"content": m.Content,
				"size":    m.Size,
			})
		}
		event["manifests"] = eventManifests
	}

	data, _ := json.Marshal(event)

	msg := kafka.Message{
		Key:   []byte(projectName),
		Value: data,
	}

	if err := w.WriteMessages(context.Background(), msg); err != nil {
		log.Printf("[KAFKA][ERR] %v", err)
		return err
	}

	log.Printf("[KAFKA] Sent CODE_SCAN_DONE for %s (manifests=%d)", projectName, len(manifests))
	return nil
}

// SaveCodeFindings persists scan results into DB
func SaveCodeFindings(projectID int, project string, findings []map[string]interface{}) {
	if len(findings) == 0 {
		return
	}

	for _, f := range findings {
		checkID := fmt.Sprintf("%v", f["check_id"])
		message := fmt.Sprintf("%v", f["extra"].(map[string]interface{})["message"])
		severity := fmt.Sprintf("%v", f["extra"].(map[string]interface{})["severity"])
		confidence := fmt.Sprintf("%v", f["extra"].(map[string]interface{})["metadata"].(map[string]interface{})["confidence"])
		category := fmt.Sprintf("%v", f["extra"].(map[string]interface{})["metadata"].(map[string]interface{})["category"])
		path := fmt.Sprintf("%v", f["path"])

		startLine := 0
		endLine := 0
		if lines, ok := f["start"].(map[string]interface{}); ok {
			startLine = int(lines["line"].(float64))
		}
		if lines, ok := f["end"].(map[string]interface{}); ok {
			endLine = int(lines["line"].(float64))
		}

		codeSnippet := ""
		if extra, ok := f["extra"].(map[string]interface{}); ok {
			if lines, ok := extra["lines"].(string); ok {
				codeSnippet = lines
			}
		}

		refLinks := []string{}
		if metadata, ok := f["extra"].(map[string]interface{})["metadata"].(map[string]interface{}); ok {
			if refs, ok := metadata["references"].([]interface{}); ok {
				for _, r := range refs {
					refLinks = append(refLinks, fmt.Sprintf("%v", r))
				}
			}
		}
		refJSON, _ := json.Marshal(refLinks)

		if _, err := db.Conn.ExecContext(context.Background(), `
			INSERT INTO code_findings (
				project_id, project_name, rule_id, rule_title, severity, confidence, category,
				message, file_path, start_line, end_line, code_snippet, reference_links, created_at
			)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())
		`, projectID, project, checkID, message, severity, confidence, category,
			message, path, startLine, endLine, codeSnippet, refJSON); err != nil {
			log.Printf("[SCAN][ERR] failed to insert code finding for project=%s: %v", project, err)
		}
	}
}

// StartCronJobs sets up Go cron to run periodic scans
func StartCronJobs() {
	c := cron.New()

	// 1) Định kỳ scan lại repo có repo_url (như cũ)
	_, err := c.AddFunc("@every 6h", func() {
		projects := []struct {
			ID      int
			Name    string
			RepoURL string
		}{}

		rows, err := db.Conn.QueryContext(context.Background(),
			"SELECT id, name, repo_url FROM projects WHERE repo_url IS NOT NULL AND is_active = TRUE")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int
				var name, repoURL string
				rows.Scan(&id, &name, &repoURL)
				projects = append(projects, struct {
					ID      int
					Name    string
					RepoURL string
				}{id, name, repoURL})
			}
		} else {
			log.Printf("[CRON][ERR] query projects: %v", err)
			return
		}

		githubToken := os.Getenv("GITHUB_TOKEN") // fallback token from env

		for _, p := range projects {
			// RunCodeScan hiện tại lookup projectID từ name,
			// vẫn dùng được, nhưng chúng ta đã có ID nếu sau này muốn tối ưu thêm.
			go RunCodeScan(p.Name, p.RepoURL, "semgrep", githubToken, 0)
		}
	})
	if err != nil {
		log.Printf("[CRON][ERR] %v", err)
	}

	c.Start()
	log.Println("[CRON] Code scan scheduler started (every 6h) + repo cleanup (daily)")
}
