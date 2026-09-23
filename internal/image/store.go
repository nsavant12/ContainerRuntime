// Package image stores verified, immutable image layers shared by all instances.
package image

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/dhruv/isolate/internal/config"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sys/unix"
)

type Manifest struct {
	Name       string   `json:"name"`
	Source     string   `json:"source"`
	Digest     string   `json:"digest,omitempty"`
	Layers     []string `json:"layers"` // base first, top last; uncompressed sha256
	Env        []string `json:"env,omitempty"`
	Entrypoint []string `json:"entrypoint,omitempty"`
	Cmd        []string `json:"cmd,omitempty"`
	Workdir    string   `json:"workdir,omitempty"`
	ImageUser  string   `json:"image_user,omitempty"`
}
type Store struct{ Root string }

func New(root string) (*Store, error) {
	p, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if p == "/" || strings.ContainsAny(p, ",:\\\n") {
		return nil, fmt.Errorf("store path cannot be / or contain comma, colon, backslash or newline")
	}
	if err = os.MkdirAll(p, 0700); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return nil, err
	}
	p = resolved
	if p == "/" || strings.ContainsAny(p, ",:\\\n") {
		return nil, fmt.Errorf("resolved store path contains unsupported mount-option characters")
	}
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("store %s must have permissions 0700", p)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("store must be owned by the current effective user")
	}
	for _, d := range []string{"images", "layers", "containers", "logs", "tmp"} {
		if err = os.MkdirAll(filepath.Join(p, d), 0700); err != nil {
			return nil, err
		}
	}
	return &Store{p}, nil
}
func (s *Store) Lock() (func(), error) {
	f, err := os.OpenFile(filepath.Join(s.Root, "images.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
func validDigest(d string) bool {
	if len(d) != 64 {
		return false
	}
	_, err := hex.DecodeString(d)
	return err == nil && strings.ToLower(d) == d
}
func (s *Store) Load(n string) (Manifest, error) {
	var m Manifest
	if err := config.Name(n); err != nil {
		return m, err
	}
	b, err := os.ReadFile(filepath.Join(s.Root, "images", n+".json"))
	if err != nil {
		return m, err
	}
	if err = json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	if len(m.Layers) == 0 || len(m.Layers) > 64 {
		return m, fmt.Errorf("image must have 1-64 layers")
	}
	for _, d := range m.Layers {
		if !validDigest(d) {
			return m, fmt.Errorf("invalid layer digest")
		}
	}
	return m, nil
}
func AtomicJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".json-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func (s *Store) save(m Manifest) error {
	return AtomicJSON(filepath.Join(s.Root, "images", m.Name+".json"), m)
}
func (s *Store) List() ([]Manifest, error) {
	entries, err := os.ReadDir(filepath.Join(s.Root, "images"))
	if err != nil {
		return nil, err
	}
	out := []Manifest{}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			m, err := s.Load(strings.TrimSuffix(e.Name(), ".json"))
			if err != nil {
				return nil, err
			}
			out = append(out, m)
		}
	}
	return out, nil
}
func (s *Store) LayerPaths(m Manifest) []string {
	out := make([]string, len(m.Layers))
	for i, d := range m.Layers {
		out[len(out)-i-1] = filepath.Join(s.Root, "layers", d)
	}
	return out
}
func (s *Store) ingest(r io.Reader, expected string) (string, error) {
	if expected != "" && !validDigest(expected) {
		return "", fmt.Errorf("invalid expected digest")
	}
	if expected != "" {
		if st, err := os.Stat(filepath.Join(s.Root, "layers", expected)); err == nil && st.IsDir() {
			return expected, nil
		}
	}
	temp, err := os.MkdirTemp(filepath.Join(s.Root, "tmp"), "layer-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(temp)
	hash := sha256.New()
	limited := &io.LimitedReader{R: r, N: 8<<30 + 1}
	tee := io.TeeReader(limited, hash)
	if err = Extract(temp, tee); err != nil {
		return "", err
	}
	if _, err = io.Copy(io.Discard, tee); err != nil {
		return "", err
	}
	if limited.N <= 0 {
		return "", fmt.Errorf("layer exceeds 8 GiB")
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if expected != "" && digest != expected {
		return "", fmt.Errorf("layer checksum mismatch: want %s got %s", expected, digest)
	}
	dest := filepath.Join(s.Root, "layers", digest)
	if _, err = os.Stat(dest); err == nil {
		return digest, nil
	}
	if err = os.Chmod(temp, 0755); err != nil {
		return "", err
	}
	if err = os.Rename(temp, dest); err != nil {
		return "", err
	}
	return digest, nil
}
func (s *Store) Pull(ctx context.Context, reference, alias string) (Manifest, error) {
	m := Manifest{Name: alias, Source: reference}
	if err := config.Name(alias); err != nil {
		return m, err
	}
	ref, err := name.ParseReference(reference)
	if err != nil {
		return m, err
	}
	img, err := remote.Image(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithPlatform(v1.Platform{OS: "linux", Architecture: runtime.GOARCH}))
	if err != nil {
		return m, err
	}
	digest, err := img.Digest()
	if err != nil {
		return m, err
	}
	m.Digest = digest.String()
	cfg, err := img.ConfigFile()
	if err != nil {
		return m, err
	}
	if cfg.OS != "linux" || cfg.Architecture != runtime.GOARCH {
		return m, fmt.Errorf("image platform %s/%s does not match linux/%s", cfg.OS, cfg.Architecture, runtime.GOARCH)
	}
	m.Env = cfg.Config.Env
	m.Cmd = cfg.Config.Cmd
	m.Entrypoint = cfg.Config.Entrypoint
	m.Workdir = cfg.Config.WorkingDir
	m.ImageUser = cfg.Config.User
	layers, err := img.Layers()
	if err != nil {
		return m, err
	}
	if len(layers) == 0 || len(layers) > 64 {
		return m, fmt.Errorf("image must have 1-64 layers")
	}
	unlock, err := s.Lock()
	if err != nil {
		return m, err
	}
	defer unlock()
	for _, layer := range layers {
		d, err := layer.DiffID()
		if err != nil {
			return m, err
		}
		if d.Algorithm != "sha256" {
			return m, fmt.Errorf("only sha256 layers supported")
		}
		r, err := layer.Uncompressed()
		if err != nil {
			return m, err
		}
		id, err := s.ingest(r, d.Hex)
		closeErr := r.Close()
		if err != nil {
			return m, err
		}
		if closeErr != nil {
			return m, closeErr
		}
		m.Layers = append(m.Layers, id)
	}
	return m, s.save(m)
}

// Import accepts a rootfs directory or an uncompressed tar archive. Layers are
// copied once into the store, so subsequent edits to the source cannot affect it.
func (s *Store) Import(source, alias string) (Manifest, error) {
	m := Manifest{Name: alias, Source: source, Workdir: "/", Env: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}}
	if err := config.Name(alias); err != nil {
		return m, err
	}
	abs, err := filepath.Abs(source)
	if err != nil {
		return m, err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return m, err
	}
	source = abs
	if abs == "/" || abs == s.Root || strings.HasPrefix(s.Root, abs+string(os.PathSeparator)) {
		return m, fmt.Errorf("source must not contain the image store")
	}
	st, err := os.Stat(source)
	if err != nil {
		return m, err
	}
	unlock, err := s.Lock()
	if err != nil {
		return m, err
	}
	defer unlock()
	var r *os.File
	if !st.IsDir() {
		r, err = os.Open(source)
	} else {
		r, err = os.CreateTemp(filepath.Join(s.Root, "tmp"), "import-")
		if err != nil {
			return m, err
		}
		defer os.Remove(r.Name())
		tw := tar.NewWriter(r)
		err = filepath.WalkDir(source, func(path string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(source, path)
			if e != nil {
				return e
			}
			if rel == "." {
				return nil
			}
			info, e := d.Info()
			if e != nil {
				return e
			}
			link := ""
			if info.Mode()&os.ModeSymlink != 0 {
				link, e = os.Readlink(path)
				if e != nil {
					return e
				}
			}
			if !info.Mode().IsRegular() && !info.IsDir() && link == "" {
				return fmt.Errorf("unsupported rootfs entry %s", rel)
			}
			h, e := tar.FileInfoHeader(info, link)
			if e != nil {
				return e
			}
			h.Name = filepath.ToSlash(rel)
			if e = tw.WriteHeader(h); e != nil {
				return e
			}
			if info.Mode().IsRegular() {
				f, e := os.Open(path)
				if e != nil {
					return e
				}
				_, e = io.Copy(tw, f)
				f.Close()
				return e
			}
			return nil
		})
		if closeErr := tw.Close(); err == nil {
			err = closeErr
		}
		if err == nil {
			_, err = r.Seek(0, io.SeekStart)
		}
	}
	if r != nil {
		defer r.Close()
	}
	if err != nil {
		return m, err
	}
	d, err := s.ingest(r, "")
	if err != nil {
		return m, err
	}
	m.Layers = []string{d}
	m.Digest = "sha256:" + d
	return m, s.save(m)
}
