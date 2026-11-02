package xray

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// HasEmbedded reports whether this build carries a usable embedded xray-core
// (i.e. the embedded archive actually contains an xray binary, not the empty
// placeholder a plain `go build` bakes in).
func HasEmbedded() bool {
	_, err := embeddedEntryName()
	return err == nil
}

// Resolve picks the xray-core binary to use. Priority: an explicit user path wins
// (falling back to PATH, as FindBinary does); otherwise the embedded copy is
// extracted and used; otherwise PATH/local discovery is the last resort.
func Resolve(explicit string) (string, error) {
	if explicit != "" {
		return FindBinary(explicit)
	}
	if p, err := ExtractEmbedded(); err == nil {
		return p, nil
	}
	return FindBinary("")
}

// embeddedEntryName returns the basename of the xray binary inside the embedded
// archive, or an error if the archive is empty/has no xray binary.
func embeddedEntryName() (string, error) {
	if len(embeddedXrayZip) == 0 {
		return "", fmt.Errorf("no embedded xray in this build")
	}
	zr, err := zip.NewReader(bytes.NewReader(embeddedXrayZip), int64(len(embeddedXrayZip)))
	if err != nil {
		return "", err
	}
	for _, f := range zr.File {
		if b := filepath.Base(f.Name); b == "xray" || b == "xray.exe" {
			return b, nil
		}
	}
	return "", fmt.Errorf("embedded archive contains no xray binary")
}

// ExtractEmbedded writes the embedded xray binary into the user cache dir and
// returns its path. The filename is keyed by a hash of the embedded bytes, so a
// rebuilt binary carrying a newer xray extracts to a fresh file and an existing,
// content-verified extraction is reused without rewriting.
func ExtractEmbedded() (string, error) {
	dir, err := cacheDir()
	if err != nil {
		return "", err
	}
	return extractEmbedded(embeddedXrayZip, embeddedXrayName, dir)
}

func extractEmbedded(archive []byte, name, dir string) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return "", err
	}

	var entry *zip.File
	for _, f := range zr.File {
		if b := filepath.Base(f.Name); b == "xray" || b == "xray.exe" {
			entry = f
			break
		}
	}
	if entry == nil {
		return "", fmt.Errorf("embedded archive contains no xray binary")
	}

	sum := sha256.Sum256(archive)
	tag := hex.EncodeToString(sum[:])[:8]
	ext := filepath.Ext(name)
	dst := filepath.Join(dir, fmt.Sprintf("xray-%s%s", tag, ext))
	rc, err := entry.Open()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, hashErr := io.Copy(hash, rc)
	closeErr := rc.Close()
	if hashErr != nil {
		return "", hashErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	want := hash.Sum(nil)
	valid := func() bool {
		fi, err := os.Lstat(dst)
		if err != nil || !fi.Mode().IsRegular() || uint64(fi.Size()) != entry.UncompressedSize64 {
			return false
		}
		if runtime.GOOS != "windows" && (fi.Mode().Perm()&0o111 != 0o111 || fi.Mode().Perm()&0o022 != 0) {
			return false
		}
		f, err := os.Open(dst)
		if err != nil {
			return false
		}
		defer f.Close()
		hash := sha256.New()
		_, err = io.Copy(hash, f)
		return err == nil && bytes.Equal(hash.Sum(nil), want)
	}
	if valid() {
		return dst, nil
	}

	rc, err = entry.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	out, err := os.CreateTemp(dir, ".xray-*")
	if err != nil {
		return "", err
	}
	tmp := out.Name()
	defer os.Remove(tmp)
	if err := out.Chmod(0o755); err != nil {
		out.Close()
		return "", err
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if valid() {
		return dst, nil
	}
	if err := os.Rename(tmp, dst); err != nil {
		// Windows may refuse replacement when a competing extractor published first.
		if valid() {
			return dst, nil
		}
		return "", err
	}
	return dst, nil
}

// cacheDir returns a writable directory for the extracted xray binary, preferring
// the per-user cache dir and falling back to the OS temp dir.
func cacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "rainscan")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		// Fall back to temp if the cache dir isn't creatable.
		dir = filepath.Join(os.TempDir(), "rainscan")
		if err2 := os.MkdirAll(dir, 0o755); err2 != nil {
			return "", err2
		}
	}
	return dir, nil
}
