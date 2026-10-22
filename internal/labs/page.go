package labs

import (
	"fmt"
	"html"
	"sort"
	"strings"
)

// indexPage renders the labs landing page: each challenge with its brief, a
// link to start, a hint ladder, and a flag-submission box that verifies.
func indexPage(selfBase string) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset=utf-8><title>Lanternfish Labs</title><style>
body{font:14px system-ui,sans-serif;margin:24px;max-width:860px;color:#1c2430}
h1{font-size:22px}.lab{border:1px solid #dde;border-radius:8px;padding:14px;margin:14px 0}
.cat{display:inline-block;background:#eef;border-radius:10px;padding:1px 8px;font-size:12px;color:#334}
.diff{font-size:12px;color:#888;margin-left:6px}a{color:#2e86de}
summary{cursor:pointer;color:#2e86de}input{padding:4px 6px}button{padding:4px 10px}
.ok{color:#1e8449;font-weight:bold}.no{color:#c0392b}code{background:#f2f4f7;padding:1px 4px;border-radius:3px}
</style></head><body>`)
	b.WriteString(`<h1>Lanternfish Labs</h1>`)
	b.WriteString(`<p>A safe, legal practice range running on your own machine. Point Lanternfish (or your browser) at a challenge, exploit the bug, read the flag it reveals, and submit it below. Every target here is intentionally vulnerable — never run these techniques on systems you do not own or have permission to test.</p>`)
	b.WriteString(`<p><b>Suggested path:</b> work top to bottom — challenges are ordered easy to hard.</p>`)

	// Order easy -> medium -> hard so the page reads as a curriculum.
	rank := map[string]int{"easy": 0, "medium": 1, "hard": 2}
	ordered := append([]Challenge(nil), Challenges...)
	sort.SliceStable(ordered, func(i, j int) bool { return rank[ordered[i].Difficulty] < rank[ordered[j].Difficulty] })

	for _, c := range ordered {
		start := html.EscapeString(c.Start)
		b.WriteString(`<div class="lab">`)
		fmt.Fprintf(&b, `<div><span class="cat">%s</span><span class="diff">%s</span></div>`,
			html.EscapeString(c.Category), html.EscapeString(c.Difficulty))
		fmt.Fprintf(&b, `<h3>%s</h3>`, html.EscapeString(c.Title))
		fmt.Fprintf(&b, `<p>%s</p>`, html.EscapeString(c.Brief))
		fmt.Fprintf(&b, `<p>Start: <a href="%s">%s</a></p>`, start, start)
		b.WriteString(`<details><summary>Hints</summary><ol>`)
		for _, h := range c.Hints {
			hint := html.EscapeString(h)
			if strings.Contains(hint, "PORT") && selfBase != "" {
				hint = strings.ReplaceAll(hint, "127.0.0.1:PORT", strings.TrimPrefix(selfBase, "http://"))
			}
			fmt.Fprintf(&b, `<li>%s</li>`, hint)
		}
		b.WriteString(`</ol></details>`)
		fmt.Fprintf(&b, `<p>Flag: <input id="f-%s" placeholder="FLAG{...}" size=34>`, c.ID)
		fmt.Fprintf(&b, ` <button onclick="verify('%s')">Submit</button> <span id="r-%s"></span></p>`, c.ID, c.ID)
		b.WriteString(`</div>`)
	}

	b.WriteString(`<script>
async function verify(id){
  const flag=document.getElementById('f-'+id).value;
  const r=await fetch('/lab/verify?id='+encodeURIComponent(id)+'&flag='+encodeURIComponent(flag));
  const d=await r.json(); const el=document.getElementById('r-'+id);
  el.textContent=d.message; el.className=d.solved?'ok':'no';
}
</script></body></html>`)
	return b.String()
}
