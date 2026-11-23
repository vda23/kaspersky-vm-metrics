package main

import (
	"crypto/sha256"
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type asset struct {
	data       []byte
	mime, etag string
	ttl        int
}

func makeAsset(data []byte, mime string, ttl int) asset {
	hash := sha256.Sum256(data)
	return asset{data, mime, fmt.Sprintf("\"%x\"", hash[:10]), ttl}
}
func loadAssets(dir string) map[string]asset {
	out := map[string]asset{}
	for path, spec := range map[string][2]string{
		"/static/app.css": {"app.css", "text/css; charset=utf-8"},
		"/static/app.js":  {"app.js", "application/javascript; charset=utf-8"},
		"/favicon.svg":    {"favicon.svg", "image/svg+xml"},
	} {
		out[path] = makeAsset(embedded("web/"+spec[0]), spec[1], 31536000)
	}
	out["/favicon.ico"] = out["/favicon.svg"]
	builtin := makeAsset(embedded("web/brand.png"), "image/png", 86400)
	exts := map[string]string{
		"svg":   "image/svg+xml",
		"png":   "image/png",
		"ttf":   "font/ttf",
		"otf":   "font/otf",
		"woff2": "font/woff2",
	}
	find := func(path, name string, ttl int, extensions ...string) {
		for _, ext := range extensions {
			for _, d := range []string{dir, filepath.Join(dir, "assets")} {
				if data, e := os.ReadFile(filepath.Join(d, name+"."+ext)); e == nil {
					out[path] = makeAsset(data, exts[ext], ttl)
					return
				}
			}
		}
	}
	for _, name := range []string{"logo", "logo-dark", "logo-light", "favicon"} {
		find("/brand/"+name, name, 86400, "svg", "png")
	}
	if _, ok := out["/brand/favicon"]; !ok {
		out["/brand/favicon"] = builtin
	}
	if out["/brand/logo"].data == nil && out["/brand/logo-light"].data == nil &&
		out["/brand/logo-dark"].data == nil {
		out["/brand/logo"] = builtin
	}
	find("/font", "KasperskySans-Regular", 604800, "ttf", "otf", "woff2")
	return out
}
func sendAsset(w http.ResponseWriter, r *http.Request, x asset) {
	w.Header().Set("Content-Type", x.mime)
	w.Header().Set("ETag", x.etag)
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(x.ttl))
	if r.Header.Get("If-None-Match") == x.etag {
		w.WriteHeader(304)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(x.data)))
	if r.Method != "HEAD" {
		w.Write(x.data)
	}
}
func (a *app) index(w http.ResponseWriter, r *http.Request) {
	pick := func(key, first, second string) string {
		q := r.URL.Query().Get(key)
		if q == first || q == second {
			http.SetCookie(
				w,
				&http.Cookie{
					Name:     "kvm_" + key,
					Value:    q,
					Path:     "/",
					MaxAge:   31536000,
					SameSite: http.SameSiteStrictMode,
					Secure:   r.TLS != nil,
				},
			)
			return q
		}
		if c, e := r.Cookie("kvm_" + key); e == nil && c.Value == second {
			return second
		}
		return first
	}
	lang, theme := pick("lang", "ru", "en"), pick("theme", "dark", "light")
	title := "Kaspersky VM | Мониторинг"
	if lang == "en" {
		title = "Kaspersky VM | Monitoring"
	}
	mark := ""
	for _, t := range []string{"dark", "light"} {
		key := "/brand/logo-" + t
		if a.static[key].data == nil {
			key = "/brand/logo"
		}
		if a.static[key].data != nil {
			mark += fmt.Sprintf(`<img class="brand-logo brand-logo-%s" src="%s" alt="">`, t, key)
		}
	}
	template := strings.NewReplacer(
		"{{LANG}}", lang,
		"{{THEME}}", theme,
		"{{TITLE}}", title,
		"{{HOST}}", html.EscapeString(a.host),
		"{{VERSION}}", version,
		"{{BRAND_MARK}}", mark,
		"{{FAVICON}}", "/brand/favicon",
		"{{STATIC_FAVICON}}", "1",
		"{{CSS_V}}", a.static["/static/app.css"].etag[1:11],
		"{{JS_V}}", a.static["/static/app.js"].etag[1:11],
	)
	body := template.Replace(string(embedded("web/index.html")))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method != "HEAD" {
		fmt.Fprint(w, body)
	}
}
