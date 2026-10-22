//go:build windows

package desktop

import (
	"errors"

	webview "github.com/jchv/go-webview2"
)

// RunNative opens a standalone native window hosting the WebView2 runtime and
// navigates it to url. It blocks until the window is closed. The window is
// owned by this process (no separate browser), giving a true desktop app.
func RunNative(url, title string) error {
	w := webview.NewWithOptions(webview.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview.WindowOptions{
			Title:  title,
			Width:  1440,
			Height: 900,
			Center: true,
		},
	})
	if w == nil {
		return errors.New("WebView2 runtime not available")
	}
	defer w.Destroy()
	w.Navigate(url)
	w.Run()
	return nil
}
