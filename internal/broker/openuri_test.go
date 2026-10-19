package broker

import "testing"

func TestValidOpenURI(t *testing.T) {
	for _, ok := range []string{"https://github.com/login/device", "http://localhost:8080/cb?x=1", "mailto:a@b.c"} {
		if err := validOpenURI(ok); err != nil {
			t.Errorf("validOpenURI(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"file:///etc/passwd", "javascript:alert(1)", "https://", "https://a.b/\nx", "", "ssh://host"} {
		if err := validOpenURI(bad); err == nil {
			t.Errorf("validOpenURI(%q) = nil, want error", bad)
		}
	}
}
