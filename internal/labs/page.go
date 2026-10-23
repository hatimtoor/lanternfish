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
.owasp{display:inline-block;background:#fdecea;color:#922;border-radius:10px;padding:1px 8px;font-size:12px;margin-left:6px}
.obj{color:#334;margin:6px 0}.res{font-size:13px}.lab.done{border-color:#1e8449;background:#f3fbf5}
.badge{float:right;color:#1e8449;font-weight:bold}
#bar{height:10px;background:#eef;border-radius:6px;overflow:hidden;margin:8px 0}
#bar > div{height:100%;background:#1e8449;width:0}
</style></head><body>`)
	b.WriteString(`<h1>Lanternfish Labs</h1>`)
	b.WriteString(`<p>A safe, legal practice range running on your own machine, mapped to the OWASP Top 10. Point Lanternfish (or your browser) at a challenge, exploit the bug, read the flag it reveals, and submit it below. Every target here is intentionally vulnerable — never run these techniques on systems you do not own or have permission to test.</p>`)
	b.WriteString(`<p><b>Learning path:</b> work top to bottom — easy to hard. Progress is saved in your browser.</p>`)
	b.WriteString(`<p id="prog"></p><div id="bar"><div></div></div>`)

	// Order easy -> medium -> hard so the page reads as a curriculum.
	rank := map[string]int{"easy": 0, "medium": 1, "hard": 2}
	ordered := append([]Challenge(nil), Challenges...)
	sort.SliceStable(ordered, func(i, j int) bool { return rank[ordered[i].Difficulty] < rank[ordered[j].Difficulty] })

	fixPort := func(s string) string {
		if selfBase != "" {
			return strings.ReplaceAll(s, "127.0.0.1:PORT", strings.TrimPrefix(selfBase, "http://"))
		}
		return s
	}
	for _, c := range ordered {
		start := html.EscapeString(c.Start)
		fmt.Fprintf(&b, `<div class="lab" id="lab-%s"><span class="badge" id="b-%s"></span>`, c.ID, c.ID)
		fmt.Fprintf(&b, `<div><span class="cat">%s</span><span class="owasp">%s</span><span class="diff">%s</span></div>`,
			html.EscapeString(c.Category), html.EscapeString(c.OWASP), html.EscapeString(c.Difficulty))
		fmt.Fprintf(&b, `<h3>%s</h3>`, html.EscapeString(c.Title))
		if c.Objective != "" {
			fmt.Fprintf(&b, `<p class="obj"><b>You'll learn:</b> %s</p>`, html.EscapeString(c.Objective))
		}
		fmt.Fprintf(&b, `<p>%s</p>`, html.EscapeString(c.Brief))
		fmt.Fprintf(&b, `<p>Start: <a href="%s">%s</a></p>`, start, start)
		b.WriteString(`<details><summary>Hints</summary><ol>`)
		for _, h := range c.Hints {
			fmt.Fprintf(&b, `<li>%s</li>`, html.EscapeString(fixPort(h)))
		}
		b.WriteString(`</ol></details>`)
		if c.Solution != "" {
			fmt.Fprintf(&b, `<details><summary>Show solution</summary><p>%s</p></details>`, html.EscapeString(fixPort(c.Solution)))
		}
		if c.Resource != "" {
			fmt.Fprintf(&b, `<p class="res">↗ <a href="%s" target="_blank" rel="noopener">Learn more (free)</a></p>`, html.EscapeString(c.Resource))
		}
		fmt.Fprintf(&b, `<p>Flag: <input id="f-%s" placeholder="FLAG{...}" size=34>`, c.ID)
		fmt.Fprintf(&b, ` <button onclick="verify('%s')">Submit</button> <span id="r-%s"></span></p>`, c.ID, c.ID)
		b.WriteString(`</div>`)
	}

	fmt.Fprintf(&b, `<script>
const TOTAL=%d;
function solvedSet(){ try{ return JSON.parse(localStorage.getItem('lf_solved')||'[]'); }catch(e){ return []; } }
function markSolved(id){ const s=solvedSet(); if(!s.includes(id)){ s.push(id); try{ localStorage.setItem('lf_solved',JSON.stringify(s)); }catch(e){} } }
function render(){
  const s=solvedSet();
  for(const id of s){ const lab=document.getElementById('lab-'+id); const bb=document.getElementById('b-'+id); if(lab)lab.classList.add('done'); if(bb)bb.textContent='✓ solved'; }
  document.getElementById('prog').textContent='Progress: '+s.length+' / '+TOTAL+' solved';
  document.querySelector('#bar > div').style.width=(TOTAL? (100*s.length/TOTAL):0)+'%%';
}
async function verify(id){
  const flag=document.getElementById('f-'+id).value;
  const r=await fetch('/lab/verify?id='+encodeURIComponent(id)+'&flag='+encodeURIComponent(flag));
  const d=await r.json(); const el=document.getElementById('r-'+id);
  el.textContent=d.message; el.className=d.solved?'ok':'no';
  if(d.solved){ markSolved(id); render(); }
}
render();
</script></body></html>`, len(ordered))
	return b.String()
}
