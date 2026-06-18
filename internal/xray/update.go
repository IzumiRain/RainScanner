package xray

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// releasesAPI is the GitHub endpoint for the latest xray-core release.
const releasesAPI = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"

// ReleaseInfo describes the installed xray-core vs the latest published release.
type ReleaseInfo struct {
	Current         string `json:"current"`          // installed version, e.g. "26.3.27" ("" if unknown)
	Latest          string `json:"latest"`           // latest published version
	Asset           string `json:"asset"`            // asset filename for this OS/arch
	DownloadURL     string `json:"-"`                // asset download URL
	UpdateAvailable bool   `json:"update_available"` // latest > current
	Supported       bool   `json:"supported"`        // an asset exists for this OS/arch
}

// assetName maps the running OS/arch to the xray-core release asset filename,
// e.g. windows/amd64 -> "Xray-windows-64.zip". Returns "" if unsupported.
func assetName() string {
	var osPart string
	switch runtime.GOOS {
	case "windows":
		osPart = "windows"
	case "linux":
		osPart = "linux"
	case "darwin":
		osPart = "macos"
	default:
		return ""
	}
	var archPart string
	switch runtime.GOARCH {
	case "amd64":
		archPart = "64"
	case "386":
		archPart = "32"
	case "arm64":
		archPart = "arm64-v8a"
	default:
		return ""
	}
	return fmt.Sprintf("Xray-%s-%s.zip", osPart, archPart)
}

// CurrentVersion runs `<binPath> version` and parses the semantic version from
// the first line ("Xray 26.3.27 (...)" -> "26.3.27").
func CurrentVersion(binPath string) (string, error) {
	out, err := exec.Command(binPath, "version").Output()
	if err != nil {
		return "", fmt.Errorf("run xray version: %w", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 || !strings.EqualFold(fields[0], "Xray") {
		return "", fmt.Errorf("unexpected version output: %q", string(out))
	}
	return strings.TrimPrefix(fields[1], "v"), nil
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// LatestRelease queries GitHub for the newest xray-core release and resolves the
// download URL of the asset matching this OS/arch.
func LatestRelease(ctx context.Context, client *http.Client) (tag, asset, downloadURL string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesAPI, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("User-Agent", "cdnscan-updater")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", "", "", fmt.Errorf("github API %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", "", "", err
	}
	want := assetName()
	if want == "" {
		return strings.TrimPrefix(rel.TagName, "v"), "", "", nil
	}
	for _, a := range rel.Assets {
		if a.Name == want {
			return strings.TrimPrefix(rel.TagName, "v"), a.Name, a.URL, nil
		}
	}
	return strings.TrimPrefix(rel.TagName, "v"), want, "", fmt.Errorf("no asset %q in release %s", want, rel.TagName)
}

// CheckUpdate compares the installed binary against the latest release.
func CheckUpdate(ctx context.Context, client *http.Client, binPath string) (ReleaseInfo, error) {
	info := ReleaseInfo{Supported: assetName() != ""}
	if cur, err := CurrentVersion(binPath); err == nil {
		info.Current = cur
	}
	tag, asset, dl, err := LatestRelease(ctx, client)
	if err != nil {
		return info, err
	}
	info.Latest, info.Asset, info.DownloadURL = tag, asset, dl
	info.UpdateAvailable = info.Current != "" && compareVersions(tag, info.Current) > 0
	return info, nil
}

// Update downloads the latest xray-core asset and replaces binPath in place. When
// includeGeo is set, geoip.dat / geosite.dat bundled in the zip are refreshed too.
// Returns the newly installed version.
func Update(ctx context.Context, client *http.Client, binPath string, includeGeo bool) (string, error) {
	if assetName() == "" {
		return "", fmt.Errorf("no xray-core build for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	_, _, downloadURL, err := LatestRelease(ctx, client)
	if err != nil {
		return "", err
	}
	if downloadURL == "" {
		return "", fmt.Errorf("no downloadable asset for this platform")
	}

	data, err := download(ctx, client, downloadURL)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("open zip: %w", err)
	}

	abs, err := filepath.Abs(binPath)
	if err != nil {
		abs = binPath
	}
	dir := filepath.Dir(abs)
	binBase := filepath.Base(abs)

	wantGeo := map[string]bool{}
	if includeGeo {
		wantGeo["geoip.dat"] = true
		wantGeo["geosite.dat"] = true
	}

	var wroteBinary bool
	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		switch {
		case base == "xray" || base == "xray.exe":
			if err := extractTo(f, filepath.Join(dir, binBase)); err != nil {
				return "", fmt.Errorf("install binary: %w", err)
			}
			wroteBinary = true
		case wantGeo[base]:
			if err := extractTo(f, filepath.Join(dir, base)); err != nil {
				return "", fmt.Errorf("install %s: %w", base, err)
			}
		}
	}
	if !wroteBinary {
		return "", fmt.Errorf("no xray binary found in release asset")
	}

	if v, err := CurrentVersion(filepath.Join(dir, binBase)); err == nil {
		return v, nil
	}
	tag, _, _, _ := LatestRelease(ctx, client)
	return tag, nil
}

// extractTo writes a zip entry to dst atomically: it streams to dst+".new", then
// renames over dst (replacing dst+".old" on Windows where the live file may be
// briefly locked). The new file is made executable.
func extractTo(f *zip.File, dst string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}

	if err := os.Rename(tmp, dst); err != nil {
		// Existing file may be locked (Windows). Shuffle it aside and retry.
		old := dst + ".old"
		os.Remove(old)
		if rerr := os.Rename(dst, old); rerr == nil {
			if err2 := os.Rename(tmp, dst); err2 != nil {
				os.Rename(old, dst) // best-effort restore
				os.Remove(tmp)
				return err2
			}
			os.Remove(old)
			return nil
		}
		os.Remove(tmp)
		return err
	}
	return nil
}

func download(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cdnscan-updater")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// compareVersions compares dotted numeric versions ("26.3.27"). Returns 1 if a>b,
// -1 if a<b, 0 if equal. Non-numeric or missing parts are treated as 0.
func compareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(strings.TrimSpace(pa[i]))
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(strings.TrimSpace(pb[i]))
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}
