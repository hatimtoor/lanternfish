//go:build !windows

package desktop

import "errors"

// RunNative is only implemented on Windows (WebView2). On other platforms the
// caller falls back to a browser app window.
func RunNative(url, title string) error {
	return errors.New("native window only supported on windows")
}
