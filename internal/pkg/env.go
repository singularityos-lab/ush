// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package pkg

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// androidRepository is Google's SDK manifest; it lists every SDK archive with
// its SHA-1, so the command-line tools are verified against Google's own index.
const androidRepository = "https://dl.google.com/android/repository/"

// Environment is a development environment installed on demand: Debian
// packages in the persistent layer, optional files under the environment
// directory, and variables exported to every later shell.
type Environment struct {
	Name     string
	Summary  string
	Packages []string
	Setup    func(ctx context.Context, dir string, stdin io.Reader, stdout, stderr io.Writer) error
	Vars     func(dir string) []string
	Note     string
}

var environments = []Environment{
	{
		Name:     "android",
		Summary:  "Android SDK: command-line tools, platform-tools, build-tools and a platform, with JDK 17",
		Packages: []string{"openjdk-17-jdk-headless", "unzip"},
		Setup:    setupAndroid,
		Vars: func(dir string) []string {
			sdk := filepath.Join(dir, "sdk")
			return []string{
				"ANDROID_HOME=" + sdk,
				"ANDROID_SDK_ROOT=" + sdk,
				"JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64",
				"PATH+=" + strings.Join([]string{
					filepath.Join(sdk, "cmdline-tools", "latest", "bin"),
					filepath.Join(sdk, "platform-tools"),
					filepath.Join(sdk, "emulator"),
				}, ":"),
			}
		},
		Note: "More SDK parts: sdkmanager --list, then sdkmanager \"<package>\".",
	},
	{
		Name:     "ios",
		Summary:  "iPhone and iPad tools: pairing, app install, file access and logs over USB",
		Packages: []string{"libimobiledevice-utils", "ideviceinstaller", "ifuse", "usbmuxd"},
		Note:     "Building iOS apps needs Apple's SDK from Xcode, which only Apple distributes; these tools talk to the device.",
	},
}

// EnvironmentsDir is where environments keep their files and variables.
func EnvironmentsDir() string {
	if d := os.Getenv("USH_STORAGE_DIR"); d != "" {
		return filepath.Join(d, "envs")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "ush", "envs")
}

func findEnvironment(name string) *Environment {
	for i := range environments {
		if environments[i].Name == name {
			return &environments[i]
		}
	}
	return nil
}

func varsFile(name string) string {
	return filepath.Join(EnvironmentsDir(), name+".env")
}

// ApplyEnvironments exports the variables of every installed environment into
// the current process, so the shell and everything it starts inherit them.
// "PATH+=" entries are appended to PATH.
func ApplyEnvironments() {
	files, _ := filepath.Glob(filepath.Join(EnvironmentsDir(), "*.env"))
	sort.Strings(files)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if k, v, ok := strings.Cut(line, "+="); ok && k == "PATH" {
				os.Setenv("PATH", os.Getenv("PATH")+":"+v)
			} else if k, v, ok := strings.Cut(line, "="); ok && k != "" {
				os.Setenv(k, v)
			}
		}
	}
}

// Env runs "pkg env": list, add NAME, remove NAME.
func (m *Manager) Env(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args []string) error {
	if len(args) == 0 || args[0] == "list" || args[0] == "ls" {
		for _, e := range environments {
			state := "available"
			if _, err := os.Stat(varsFile(e.Name)); err == nil {
				state = "installed"
			}
			fmt.Fprintf(stdout, "  %-8s %-10s %s\n", e.Name, state, e.Summary)
		}
		return nil
	}
	if len(args) < 2 {
		fmt.Fprintln(stderr, "pkg env: usage: pkg env [list|add NAME|remove NAME]")
		return fmt.Errorf("missing environment")
	}
	e := findEnvironment(args[1])
	if e == nil {
		fmt.Fprintf(stderr, "pkg env: unknown environment '%s'\n", args[1])
		return fmt.Errorf("unknown environment")
	}
	dir := filepath.Join(EnvironmentsDir(), e.Name)
	switch args[0] {
	case "add", "install":
		if err := m.Install(ctx, stdout, stderr, e.Packages); err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if e.Setup != nil {
			if m.brokerClient != nil && !m.brokerClient.IsAllowed("network", "pkg-env", "download the "+e.Name+" environment") {
				fmt.Fprintln(stderr, "pkg env: network access denied by user")
				return fmt.Errorf("permission denied")
			}
			if err := e.Setup(ctx, dir, stdin, stdout, stderr); err != nil {
				fmt.Fprintf(stderr, "pkg env: %s: %v\n", e.Name, err)
				return err
			}
		}
		var vars []string
		if e.Vars != nil {
			vars = e.Vars(dir)
		}
		if err := os.WriteFile(varsFile(e.Name), []byte(strings.Join(vars, "\n")+"\n"), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "pkg env: %s ready. Open a new shell (or run 'restart') to load its variables.\n", e.Name)
		if e.Note != "" {
			fmt.Fprintln(stdout, e.Note)
		}
		return nil
	case "remove", "rm":
		os.Remove(varsFile(e.Name))
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
		return m.Remove(ctx, stdout, stderr, e.Packages)
	}
	fmt.Fprintf(stderr, "pkg env: unknown command '%s'\n", args[0])
	return fmt.Errorf("unknown command")
}

type sdkRepository struct {
	Packages []struct {
		Path     string `xml:"path,attr"`
		Archives []struct {
			URL      string `xml:"complete>url"`
			Checksum string `xml:"complete>checksum"`
			HostOS   string `xml:"host-os"`
		} `xml:"archives>archive"`
	} `xml:"remotePackage"`
}

// commandLineTools returns the Linux archive of "cmdline-tools;latest" and its SHA-1.
func commandLineTools(manifest io.Reader) (string, string, error) {
	var repo sdkRepository
	if err := xml.NewDecoder(manifest).Decode(&repo); err != nil {
		return "", "", err
	}
	for _, p := range repo.Packages {
		if p.Path != "cmdline-tools;latest" {
			continue
		}
		for _, a := range p.Archives {
			if a.HostOS == "linux" && a.URL != "" && len(a.Checksum) == 40 {
				return a.URL, strings.ToLower(a.Checksum), nil
			}
		}
	}
	return "", "", fmt.Errorf("no Linux command-line tools in the SDK manifest")
}

func download(ctx context.Context, url, dest, sha string, stdout io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	sum := sha1.New()
	fmt.Fprintf(stdout, "pkg env: downloading %s\n", filepath.Base(url))
	if _, err := io.Copy(io.MultiWriter(out, sum), resp.Body); err != nil {
		return err
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != sha {
		os.Remove(dest)
		return fmt.Errorf("%s: checksum %s, expected %s", filepath.Base(url), got, sha)
	}
	return nil
}

func unzip(archive, dest, strip string) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		name := strings.TrimPrefix(f.Name, strip)
		target := filepath.Join(dest, name)
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
			continue
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0o755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		src, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode()|0o600)
		if err != nil {
			src.Close()
			return err
		}
		_, err = io.Copy(out, src)
		src.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func setupAndroid(ctx context.Context, dir string, stdin io.Reader, stdout, stderr io.Writer) error {
	sdk := filepath.Join(dir, "sdk")
	tools := filepath.Join(sdk, "cmdline-tools", "latest")
	sdkmanager := filepath.Join(tools, "bin", "sdkmanager")
	if _, err := os.Stat(sdkmanager); err != nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, androidRepository+"repository2-3.xml", nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		url, sha, err := commandLineTools(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		archive := filepath.Join(dir, "cmdline-tools.zip")
		if err := download(ctx, androidRepository+url, archive, sha, stdout); err != nil {
			return err
		}
		defer os.Remove(archive)
		os.RemoveAll(tools)
		if err := unzip(archive, tools, "cmdline-tools/"); err != nil {
			return err
		}
	}
	env := append(os.Environ(), "JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64", "ANDROID_HOME="+sdk)
	fmt.Fprintln(stdout, "pkg env: review and accept the Android SDK licenses")
	licenses := exec.CommandContext(ctx, sdkmanager, "--sdk_root="+sdk, "--licenses")
	licenses.Env, licenses.Stdin, licenses.Stdout, licenses.Stderr = env, stdin, stdout, stderr
	if err := licenses.Run(); err != nil {
		return fmt.Errorf("licenses: %w", err)
	}
	install := exec.CommandContext(ctx, sdkmanager, "--sdk_root="+sdk, "platform-tools", "build-tools;35.0.0", "platforms;android-35")
	install.Env, install.Stdout, install.Stderr = env, stdout, stderr
	install.Stdin = bufio.NewReader(strings.NewReader(""))
	return install.Run()
}
