// SPDX-License-Identifier: MIT
// kit/procedure/md.mjs — the Markdown subset the kit's procedures use, rendered to HTML.
// print.mjs prefers site/build.mjs's renderer when the kit sits in a sigelo clone; an installed
// kit has no site/, so this is what renders there. No raw HTML passes: every `<` is escaped.
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function inline(s) {
  const slots = [];
  const keep = (h) => `\u0000${slots.push(h) - 1}\u0000`;
  s = s.replace(/`([^`]+)`/g, (_, c) => keep(`<code>${esc(c)}</code>`));
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, t, u) => keep(`<a href="${esc(u)}">${esc(t)}</a>`));
  s = esc(s).replace(/\*\*(?=\S)([\s\S]*?\S)\*\*/g, '<strong>$1</strong>').replace(/(^|[^\w*])\*(?=[^\s*])([^*]*?[^\s*])\*(?!\w)/g, '$1<em>$2</em>');
  return s.replace(/\u0000(\d+)\u0000/g, (_, n) => slots[+n]);
}
const cells = (l) => l.trim().replace(/^\||\|$/g, '').split(/(?<!\\)\|(?=(?:[^`]*`[^`]*`)*[^`]*$)/).map((c) => c.trim());

export function render(md) {
  const L = md.replace(/\r\n?/g, '\n').split('\n'), out = [];
  let i = 0;
  while (i < L.length) {
    const l = L[i];
    if (/^\s*$/.test(l)) { i++; continue; }
    const f = l.match(/^(`{3,})(\w*)/);
    if (f) { const b = []; i++; while (i < L.length && !L[i].startsWith(f[1])) b.push(L[i++]); i++; out.push(`<pre><code>${esc(b.join('\n'))}</code></pre>`); continue; }
    const h = l.match(/^(#{1,6})\s+(.*)$/);
    if (h) { out.push(`<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`); i++; continue; }
    if (/^(-{3,}|\*{3,})\s*$/.test(l)) { out.push('<hr>'); i++; continue; }
    if (/^>/.test(l)) { const b = []; while (i < L.length && /^>/.test(L[i])) b.push(L[i++].replace(/^> ?/, '')); out.push(`<blockquote>\n${render(b.join('\n'))}\n</blockquote>`); continue; }
    if (l.trim().startsWith('|') && /^\s*\|?[\s:|-]+\|?\s*$/.test(L[i + 1] ?? '') && (L[i + 1] ?? '').includes('-')) {
      const head = cells(l); i += 2; const rows = [];
      while (i < L.length && L[i].trim().startsWith('|')) rows.push(cells(L[i++]));
      out.push(`<div class="table"><table>\n<thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join('')}</tr></thead>\n<tbody>\n${rows.map((r) => `<tr>${head.map((_, k) => `<td>${inline(r[k] ?? '')}</td>`).join('')}</tr>`).join('\n')}\n</tbody></table></div>`);
      continue;
    }
    const li = l.match(/^(\s*)([-*]|\d+\.)\s+(.*)$/);
    if (li) {
      const tag = /\d/.test(li[2]) ? 'ol' : 'ul', items = [];
      while (i < L.length) {
        const m = L[i].match(/^(\s*)([-*]|\d+\.)\s+(.*)$/);
        if (m && m[1].length === li[1].length) { items.push([m[3]]); i++; continue; }
        if (/^\s*$/.test(L[i]) && /^\s+\S|^\s*([-*]|\d+\.)\s/.test(L[i + 1] ?? '') && (L[i + 1].match(/^\s*/)[0].length > li[1].length || /^\s*([-*]|\d+\.)\s/.test(L[i + 1]))) { items.at(-1).push(''); i++; continue; }
        if (/^\s+\S/.test(L[i]) && items.length) { items.at(-1).push(L[i].replace(/^\s{1,3}/, '')); i++; continue; }
        break;
      }
      out.push(`<${tag}>${items.map((b) => `<li>${b.some((x) => /^(```|\s*[-*]\s|\s*\d+\.\s)/.test(x)) ? render(b.join('\n')) : inline(b.filter(Boolean).join(' '))}</li>`).join('\n')}</${tag}>`);
      continue;
    }
    const p = [];
    while (i < L.length && !/^\s*$/.test(L[i]) && !/^(#{1,6}\s|```|>|\s*([-*]|\d+\.)\s|\|)/.test(L[i])) p.push(L[i++].trim());
    if (p.length === 0) { out.push(`<p>${inline(L[i++].trim())}</p>`); continue; }
    out.push(`<p>${inline(p.join('\n'))}</p>`);
  }
  return out.join('\n');
}
