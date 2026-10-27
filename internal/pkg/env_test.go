package pkg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const manifest = `<?xml version="1.0"?>
<sdk:sdk-repository xmlns:sdk="http://schemas.android.com/sdk/android/repo/repository2/03">
  <remotePackage path="cmdline-tools;12.0">
    <archives><archive><complete><size>1</size><checksum type="sha1">0000000000000000000000000000000000000000</checksum><url>old.zip</url></complete><host-os>linux</host-os></archive></archives>
  </remotePackage>
  <remotePackage path="cmdline-tools;latest">
    <archives>
      <archive><complete><size>2</size><checksum type="sha1">112CF9618794A997FF273537D55BEE02C22ABFFE</checksum><url>mac.zip</url></complete><host-os>macosx</host-os></archive>
      <archive><complete><size>3</size><checksum type="sha1">E025545C62A8E64C7559119566A569FB1DEC5F60</checksum><url>commandlinetools-linux-1_latest.zip</url></complete><host-os>linux</host-os></archive>
    </archives>
  </remotePackage>
</sdk:sdk-repository>`

func TestCommandLineToolsPicksTheLinuxLatestArchive(t *testing.T) {
	url, sha, err := commandLineTools(strings.NewReader(manifest))
	if err != nil {
		t.Fatal(err)
	}
	if url != "commandlinetools-linux-1_latest.zip" || sha != "e025545c62a8e64c7559119566a569fb1dec5f60" {
		t.Fatalf("got %s %s", url, sha)
	}
}

func TestApplyEnvironmentsExportsVariablesAndAppendsPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("USH_STORAGE_DIR", dir)
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("ANDROID_HOME", "")
	os.MkdirAll(filepath.Join(dir, "envs"), 0o755)
	os.WriteFile(filepath.Join(dir, "envs", "android.env"), []byte("ANDROID_HOME=/sdk\nPATH+=/sdk/platform-tools\n"), 0o644)
	ApplyEnvironments()
	if os.Getenv("ANDROID_HOME") != "/sdk" {
		t.Fatalf("ANDROID_HOME=%q", os.Getenv("ANDROID_HOME"))
	}
	if os.Getenv("PATH") != "/usr/bin:/sdk/platform-tools" {
		t.Fatalf("PATH=%q", os.Getenv("PATH"))
	}
}

func TestUnknownEnvironmentIsRejected(t *testing.T) {
	if findEnvironment("windows") != nil || findEnvironment("android") == nil || findEnvironment("ios") == nil {
		t.Fatal("unexpected environment table")
	}
}
