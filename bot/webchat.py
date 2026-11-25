"""DARWIN DZ Web Chat: a standalone website for the AI chat, separate from the admin panel.

Own server, own port (WEB_CHAT_PORT), own cookie, own password, own session store. Nothing from the admin panel is shared except the
AI client, so a problem here can never expose the user-management panel (and the reverse).

Access: a password (WEB_CHAT_PASSWORD, or one derived from the bot token: admins get it with /webchat) or, with WEB_CHAT_PUBLIC=1, open
to everyone behind per-IP / per-session / daily limits. History lives only in the visitor's session (memory), never in the database.
Security model: HttpOnly + SameSite=Strict cookie, CSRF header on every POST, per-request CSP nonce (the only script is ours),
no innerHTML anywhere in the page script (model output is rendered with DOM text nodes), Host allow-list against DNS rebinding.
"""
from __future__ import annotations

import hmac
import html
import json
import logging
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlsplit

from .ai_client import APIError
from .brand import CORE_PROMPT
from .hardening import SAFETY_TAIL, LimitedHTTPServer, cross_site
from .personas import PERSONAS
from .webext import WEB_TOOLS, run_web_tool

log = logging.getLogger("bot.webchat")

COOKIE = "dzc_sid"
SESSION_TTL = 12 * 3600
LOGIN_FAILS, LOGIN_WINDOW = 5, 300
MAX_BODY = 64 * 1024
MAX_INPUT = 4000
MAX_MSGS = 24                    # messages kept per session
MAX_CONTEXT_CHARS = 24000
MAX_SESSIONS = 5000
RATE = (12, 60)                  # messages per window (seconds) per session
TOOL_RATE = (30, 60)             # tool runs per window per session
TOOL_IP_RATE = (90, 60)          # tool runs per window per IP (same window length as IP_RATE)
TOOL_OUT_MAX = 20000
IP_RATE = (30, 60)               # messages per window per IP (covers people who clear cookies)
LOOPBACK = ("127.0.0.1", "localhost", "[::1]", "::1")


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""), quote=True)


SEC = {
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store", "Cross-Origin-Resource-Policy": "same-origin", "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(self), geolocation=(), payment=(), usb=(), interest-cohort=()",
}

# Light theme variables (used twice: system preference and the manual toggle).
_LIGHT = "color-scheme:light;--bg:#f3f4f6;--glass:rgba(255,255,255,.72);--glass2:rgba(255,255,255,.96);--fg:#0b0c0e;--mut:#5a606b;--line:rgba(10,12,16,.12);--silver:linear-gradient(135deg,#050506 0%,#3a3e46 50%,#7b818c 100%);--shim:linear-gradient(100deg,#050506 0%,#7b818c 25%,#050506 50%,#7b818c 75%,#050506 100%);--mebg:linear-gradient(135deg,#101113,#32353c);--mefg:#fff;--bad:#c62828;--g1:rgba(120,126,138,.22);--g2:rgba(170,176,188,.32);--sh:0 10px 36px rgba(20,22,28,.12)"

CSS = r"""
:root{color-scheme:dark;--bg:#050506;--glass:rgba(255,255,255,.045);--glass2:rgba(255,255,255,.09);--fg:#f2f3f5;--mut:#9aa0aa;--line:rgba(255,255,255,.11);--silver:linear-gradient(135deg,#fff 0%,#cfd3da 40%,#8d939d 100%);--shim:linear-gradient(100deg,#fff 0%,#8f95a0 25%,#fff 50%,#8f95a0 75%,#fff 100%);--mebg:linear-gradient(135deg,#f4f5f7,#b4b9c2);--mefg:#08090a;--code:#0b0c0e;--codefg:#e8eaee;--bad:#ff6b6b;--g1:rgba(210,214,222,.15);--g2:rgba(120,126,138,.15);--sh:0 10px 40px rgba(0,0,0,.55)}
@media (prefers-color-scheme:light){:root:not([data-theme]){@@L@@}}
:root[data-theme=light]{@@L@@}
*{box-sizing:border-box}html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.75 "Segoe UI",Tahoma,"Noto Sans Arabic",system-ui,sans-serif;display:flex;flex-direction:column;overflow:hidden;position:relative;-webkit-font-smoothing:antialiased}
body::before{content:"";position:fixed;inset:-25%;z-index:-2;background:radial-gradient(40% 35% at 25% 20%,var(--g1),transparent 70%),radial-gradient(35% 40% at 80% 30%,var(--g2),transparent 70%),radial-gradient(45% 40% at 55% 90%,var(--g1),transparent 70%);animation:drift 26s ease-in-out infinite alternate;will-change:transform}
body::after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background:linear-gradient(115deg,transparent 40%,rgba(255,255,255,.045) 50%,transparent 60%);background-size:250% 100%;animation:sheen 10s linear infinite}
@keyframes drift{to{transform:translate3d(4%,3%,0) rotate(8deg) scale(1.08)}}
@keyframes sheen{from{background-position:150% 0}to{background-position:-150% 0}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes shine{to{background-position:-200% 0}}
@keyframes rise{from{opacity:0;transform:translateY(10px) scale(.985);filter:blur(4px)}}
@keyframes blink{50%{opacity:0}}
@keyframes pulse{0%,80%,100%{opacity:.2;transform:scale(.7)}40%{opacity:1;transform:scale(1)}}
.orb{display:inline-block;width:30px;height:30px;border-radius:50%;background:conic-gradient(from 0deg,#fff,#7d838d,#d9dce2,#555a63,#fff);animation:spin 8s linear infinite;box-shadow:0 0 18px rgba(200,205,215,.35),inset 0 0 6px rgba(0,0,0,.4);flex:none}
h1,.hero h2{background:var(--shim);background-size:200% 100%;-webkit-background-clip:text;background-clip:text;color:transparent;animation:shine 6s linear infinite}
header{display:flex;gap:8px;align-items:center;padding:12px 16px;border-bottom:1px solid var(--line);background:var(--glass);-webkit-backdrop-filter:blur(18px) saturate(1.4);backdrop-filter:blur(18px) saturate(1.4);position:relative;z-index:3}
.brand{display:flex;align-items:center;gap:10px;flex:1;min-width:0}
header h1{font-size:18px;margin:0;font-weight:700;letter-spacing:.08em;white-space:nowrap}
button,select,textarea,input{font:inherit;color:var(--fg)}
.btn,select{background:var(--glass);border:1px solid var(--line);border-radius:12px;padding:7px 12px;font-size:14px;cursor:pointer;transition:background .25s,transform .25s,border-color .25s}
.btn:hover,select:hover{background:var(--glass2);transform:translateY(-1px);border-color:var(--mut)}
select{max-width:44vw;text-overflow:ellipsis}select option{background:#121315;color:#eee}
#log{flex:1;overflow-y:auto;padding:26px max(14px,calc((100% - 820px)/2)) 12px;display:flex;flex-direction:column;gap:20px;scroll-behavior:smooth;position:relative;z-index:1;scrollbar-width:thin;scrollbar-color:var(--line) transparent}
.row{display:flex;gap:12px;animation:rise .45s cubic-bezier(.2,.8,.2,1) both}
.av{flex:none;width:32px;height:32px;border-radius:50%;display:grid;place-items:center;font-weight:700;font-size:14px;background:var(--silver);color:var(--bg);margin-top:2px;box-shadow:0 0 14px rgba(200,205,215,.25)}
.msg{min-width:0;overflow-wrap:anywhere}
.row.me .msg{background:var(--mebg);color:var(--mefg);padding:10px 16px;border-radius:20px 20px 6px 20px;max-width:86%;box-shadow:var(--sh)}
.row.me .msg p{margin:0;white-space:pre-wrap}
.row.ai .msg{flex:1;padding-top:2px}
.msg p{margin:.45em 0;white-space:pre-wrap}.msg>:first-child{margin-top:0}
.msg h2,.msg h3,.msg h4,.msg h5{margin:1.1em 0 .3em;line-height:1.35}.msg h2{font-size:1.32em}.msg h3{font-size:1.16em}.msg h4,.msg h5{font-size:1.02em}
.msg ul,.msg ol{padding-inline-start:1.5em;margin:.5em 0}.msg li{margin:.2em 0}
.msg a{color:inherit;text-decoration:underline;text-underline-offset:3px}
.msg blockquote{margin:.6em 0;padding:.2em 1em;border-inline-start:3px solid var(--mut);color:var(--mut);white-space:pre-wrap}
.msg hr{border:0;height:1px;background:var(--line);margin:1em 0}
.msg code{background:var(--glass2);border:1px solid var(--line);border-radius:6px;padding:1px 6px;font-family:ui-monospace,"SF Mono",Consolas,monospace;font-size:.88em;direction:ltr;unicode-bidi:isolate}
.cb{margin:.8em 0;border:1px solid var(--line);border-radius:14px;overflow:hidden;background:var(--code);direction:ltr;box-shadow:var(--sh)}
.ch{display:flex;justify-content:space-between;align-items:center;padding:6px 12px;font-size:12px;font-family:ui-monospace,Consolas,monospace;color:#9aa0aa;border-bottom:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.04)}
.cb pre{margin:0;padding:12px 14px;overflow-x:auto;text-align:left}
.cb code{background:none;border:0;padding:0;color:var(--codefg);font-size:.9em;line-height:1.65;white-space:pre}
.cp{background:none;border:1px solid rgba(255,255,255,.18);color:#cfd3da;border-radius:8px;padding:2px 10px;font-size:12px;cursor:pointer;transition:background .2s}.cp:hover{background:rgba(255,255,255,.12)}
.tw{overflow-x:auto;margin:.8em 0;border:1px solid var(--line);border-radius:12px}
table{border-collapse:collapse;width:100%;font-size:.93em}th,td{padding:8px 12px;border-bottom:1px solid var(--line);text-align:start}th{background:var(--glass2)}tr:last-child td{border-bottom:0}
.act{display:flex;gap:6px;margin-top:8px;opacity:0;transition:opacity .25s}.row:hover .act,.act:focus-within{opacity:1}
@media (hover:none){.act{opacity:.85}}
.act button{background:none;border:1px solid var(--line);border-radius:9px;padding:2px 10px;font-size:12px;color:var(--mut);cursor:pointer;transition:.2s}.act button:hover{color:var(--fg);background:var(--glass2)}
.typing p:last-of-type::after,.typing li:last-of-type::after{content:"";display:inline-block;width:7px;height:1.05em;margin-inline-start:3px;vertical-align:-.15em;background:var(--fg);border-radius:2px;animation:blink 1s steps(2) infinite}
.think{display:flex;align-items:center;gap:7px;color:var(--mut);font-size:14px;padding-top:8px}
.think i{width:8px;height:8px;border-radius:50%;background:var(--fg);display:inline-block;animation:pulse 1.2s ease-in-out infinite}.think i:nth-child(2){animation-delay:.15s}.think i:nth-child(3){animation-delay:.3s}.think span{margin-inline-start:6px}
.hero{margin:auto;text-align:center;max-width:680px;width:100%;animation:rise .7s both}
.hero .orb{width:64px;height:64px;margin-bottom:16px}
.hero h2{font-size:clamp(26px,6vw,38px);margin:0 0 6px;letter-spacing:.05em}
.hero p{color:var(--mut);margin:0 0 26px}
.chips{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px}
.chip{text-align:start;padding:13px 15px;border-radius:15px;border:1px solid var(--line);background:var(--glass);cursor:pointer;font-size:14px;line-height:1.55;transition:transform .25s,background .25s,border-color .25s}
.chip:hover{transform:translateY(-3px);background:var(--glass2);border-color:var(--mut)}
.err{align-self:center;color:var(--bad);font-size:14px;display:flex;gap:10px;align-items:center;padding:8px 14px;border:1px solid var(--bad);border-radius:12px;background:var(--glass);animation:rise .3s both}
.err button{background:none;border:1px solid currentColor;color:inherit;border-radius:8px;padding:1px 10px;cursor:pointer;font-size:13px}
.dock{padding:6px max(12px,calc((100% - 820px)/2)) max(14px,env(safe-area-inset-bottom));position:relative;z-index:3}
form#f{display:flex;align-items:flex-end;gap:8px;padding:8px;border:1px solid var(--line);border-radius:26px;background:var(--glass);-webkit-backdrop-filter:blur(20px);backdrop-filter:blur(20px);box-shadow:var(--sh);transition:border-color .3s,box-shadow .3s}
form#f:focus-within{border-color:var(--mut);box-shadow:var(--sh),0 0 0 4px var(--g1)}
form#f textarea{flex:1;resize:none;min-height:44px;max-height:200px;background:none;border:0;outline:0;padding:10px 12px;line-height:1.6}
textarea::placeholder{color:var(--mut)}
#s{flex:none;width:44px;height:44px;border-radius:50%;border:0;background:var(--silver);color:var(--bg);font-size:20px;font-weight:700;cursor:pointer;display:grid;place-items:center;transition:transform .25s,opacity .25s,box-shadow .25s}
#s:hover:not(:disabled){transform:scale(1.08) rotate(-8deg);box-shadow:0 0 22px rgba(200,205,215,.4)}#s:disabled{opacity:.4;cursor:wait}
.meta{display:flex;justify-content:space-between;font-size:12px;color:var(--mut);padding:7px 14px 0}
#dn{position:absolute;top:-48px;left:50%;transform:translate(-50%,8px);opacity:0;pointer-events:none;border-radius:50%;width:38px;height:38px;padding:0;-webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px)}
#dn.show{opacity:1;pointer-events:auto;transform:translate(-50%,0)}
.login{width:min(92vw,400px);margin:auto;padding:34px 28px;background:var(--glass);border:1px solid var(--line);border-radius:28px;-webkit-backdrop-filter:blur(22px);backdrop-filter:blur(22px);box-shadow:var(--sh);text-align:center;animation:rise .7s both}
.login .orb{width:58px;height:58px;margin-bottom:12px}
.login h1{margin:0 0 4px;font-size:26px;letter-spacing:.08em}
.login input{width:100%;margin:16px 0 10px;padding:13px 14px;border-radius:14px;border:1px solid var(--line);background:var(--glass);outline:0;transition:border-color .25s,box-shadow .25s}
.login input:focus{border-color:var(--mut);box-shadow:0 0 0 4px var(--g1)}
.login button{width:100%;padding:12px;border:0;border-radius:14px;background:var(--silver);color:var(--bg);font-weight:700;cursor:pointer;transition:transform .25s,box-shadow .25s}
.login button:hover{transform:translateY(-2px);box-shadow:0 0 24px rgba(200,205,215,.35)}
.flash{color:var(--bad);margin:8px 0}.mut{color:var(--mut);font-size:13px}
select{flex:none}#th{min-width:38px;font-size:18px;line-height:1}
@media (max-width:640px){header{padding:10px 12px;flex-wrap:wrap}.brand{flex:1 1 auto}header h1{font-size:16px}.btn,select{padding:6px 10px}header select{order:5;flex:1 1 100%;max-width:none}.row{gap:8px}.av{width:28px;height:28px}}
[hidden]{display:none!important}
@keyframes fade{from{opacity:0}}@keyframes rec{50%{box-shadow:0 0 0 9px rgba(255,107,107,.22)}}
.sheet{position:fixed;inset:0;z-index:20;display:grid;place-items:center;padding:14px;background:rgba(0,0,0,.55);-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px);animation:fade .25s both}
.panel{width:min(100%,640px);max-height:92vh;overflow:auto;display:flex;flex-direction:column;gap:10px;padding:16px;border:1px solid var(--line);border-radius:24px;background:var(--bg);box-shadow:var(--sh);animation:rise .35s cubic-bezier(.2,.8,.2,1) both}
.ph{display:flex;justify-content:space-between;align-items:center}
.panel input,.panel select,.panel textarea{width:100%;max-width:none;background:var(--glass);border:1px solid var(--line);border-radius:12px;padding:10px 12px;outline:0;transition:border-color .25s}
.panel input:focus,.panel select:focus,.panel textarea:focus{border-color:var(--mut)}.panel textarea{resize:vertical;min-height:90px;line-height:1.6}
.pb{display:flex;gap:8px;flex-wrap:wrap}.btn.pri{background:var(--silver);color:var(--bg);border:0;font-weight:700}
#to{margin:0;padding:12px;border:1px solid var(--line);border-radius:12px;background:var(--code);color:var(--codefg);white-space:pre-wrap;overflow-wrap:anywhere;min-height:56px;max-height:38vh;overflow:auto;font:13px/1.65 ui-monospace,Consolas,monospace;text-align:start;unicode-bidi:plaintext}
#to:empty{display:none}#to.bad{color:#ff8a8a}
#mic{flex:none;width:44px;height:44px;border-radius:50%;border:1px solid var(--line);background:none;cursor:pointer;font-size:18px;transition:background .25s,transform .25s}#mic:hover{background:var(--glass2);transform:scale(1.06)}
#mic.on{background:var(--bad);animation:rec 1.2s ease-in-out infinite}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
""".replace("@@L@@", _LIGHT)

# The page script. No DOM-string injection: every piece of model/user text goes through text nodes.
JS = r"""
(()=>{
const $=s=>document.querySelector(s),log=$('#log'),form=$('#f'),box=$('#m'),send=$('#s'),dn=$('#dn'),cnt=$('#cnt'),root=document.documentElement;
const csrf=root.dataset.csrf,MAX=+box.maxLength||4000;let busy=false,skip=null,H=[];
const mk=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e};
const reduce=matchMedia('(prefers-reduced-motion:reduce)').matches;
const near=()=>log.scrollHeight-log.scrollTop-log.clientHeight<150;
const stick=f=>{if(f||near())log.scrollTo({top:log.scrollHeight,behavior:f?'smooth':'auto'})};
log.addEventListener('scroll',()=>dn.classList.toggle('show',!near()));
dn.onclick=()=>stick(true);
// theme: system by default, then dark -> light -> system
const TK='dz_theme';let th=null;try{th=localStorage.getItem(TK)}catch(e){}
const applyTheme=v=>{if(v==='dark'||v==='light')root.dataset.theme=v;else delete root.dataset.theme};applyTheme(th);
$('#th').onclick=()=>{th=th==='dark'?'light':th==='light'?null:'dark';applyTheme(th);try{th?localStorage.setItem(TK,th):localStorage.removeItem(TK)}catch(e){}
 $('#th').title=th==='dark'?'داكن':th==='light'?'فاتح':'تلقائي'};
// inline markdown (text nodes only)
function inline(p,t){const re=/(`[^`\n]+`|\*\*[^*\n]+\*\*|\*(?!\s)[^*\n]+?(?<!\s)\*|\[[^\]\n]+\]\(https?:\/\/[^\s)]+\))/g;let i=0,m;
 while((m=re.exec(t))){if(m.index>i)p.append(t.slice(i,m.index));const s=m[0];let el;
  if(s[0]==='`')el=mk('code','',s.slice(1,-1));
  else if(s.startsWith('**'))el=mk('b','',s.slice(2,-2));
  else if(s[0]==='*')el=mk('i','',s.slice(1,-1));
  else{const k=s.indexOf('](');el=mk('a','',s.slice(1,k));el.href=s.slice(k+2,-1);el.target='_blank';el.rel='noopener noreferrer nofollow'}
  p.append(el);i=m.index+s.length}
 if(i<t.length)p.append(t.slice(i))}
const LI=/^\s*(?:[-*•]|\d+[.)])\s+(.*)$/,TR=/^\s*\|.*\|\s*$/;
function blocks(el,seg){const L=seg.split('\n');let i=0,m;
 while(i<L.length){const ln=L[i];if(!ln.trim()){i++;continue}
  if((m=/^(#{1,4})\s+(.*)$/.exec(ln))){const h=mk('h'+(m[1].length+1));inline(h,m[2]);el.append(h);i++;continue}
  if(/^\s*([-*_])(\s*\1){2,}\s*$/.test(ln)){el.append(mk('hr'));i++;continue}
  if(/^\s*>/.test(ln)){const q=mk('blockquote'),buf=[];while(i<L.length&&/^\s*>/.test(L[i])){buf.push(L[i].replace(/^\s*>\s?/,''));i++}inline(q,buf.join('\n'));el.append(q);continue}
  if(LI.test(ln)){const l=mk(/^\s*\d/.test(ln)?'ol':'ul');while(i<L.length&&(m=LI.exec(L[i]))){const li=mk('li');inline(li,m[1]);l.append(li);i++}el.append(l);continue}
  if(TR.test(ln)&&i+1<L.length&&/^\s*\|?\s*:?-{2,}/.test(L[i+1])){
   const cells=s=>s.trim().replace(/^\||\|$/g,'').split('|').map(x=>x.trim());
   const w=mk('div','tw'),tb=mk('table'),th=mk('thead'),tr=mk('tr');cells(ln).forEach(c=>{const x=mk('th');inline(x,c);tr.append(x)});th.append(tr);tb.append(th);i+=2;
   const bd=mk('tbody');while(i<L.length&&TR.test(L[i])){const r=mk('tr');cells(L[i]).forEach(c=>{const x=mk('td');inline(x,c);r.append(x)});bd.append(r);i++}
   tb.append(bd);w.append(tb);el.append(w);continue}
  const buf=[];while(i<L.length&&L[i].trim()&&!/^(#{1,4}\s|\s*>|\s*([-*•]|\d+[.)])\s)/.test(L[i])){buf.push(L[i]);i++}
  if(!buf.length){buf.push(L[i]);i++}
  const p=mk('p');inline(p,buf.join('\n'));el.append(p)}}
const copy=(txt,b,label)=>{navigator.clipboard&&navigator.clipboard.writeText(txt).then(()=>{b.textContent='✓';setTimeout(()=>b.textContent=label,1300)})};
function render(el,text){el.textContent='';
 text.split(/```/).forEach((seg,idx)=>{
  if(idx%2){const nl=seg.indexOf('\n'),lang=nl>=0?seg.slice(0,nl).trim().slice(0,20):'',body=(nl>=0?seg.slice(nl+1):seg).replace(/\n$/,'');
   const w=mk('div','cb'),hd=mk('div','ch'),pre=mk('pre'),code=mk('code','',body),b=mk('button','cp','نسخ');b.type='button';
   b.onclick=()=>copy(code.textContent,b,'نسخ');hd.append(mk('span','',lang||'code'),b);pre.append(code);w.append(hd,pre);el.append(w)}
  else blocks(el,seg)})}
// typewriter reveal; click or Esc finishes it
function reveal(el,text,done){
 if(reduce||document.hidden){render(el,text);done();return}
 let n=0,stop=false;const step=Math.max(3,Math.ceil(text.length/150));
 skip=()=>{stop=true};el.classList.add('typing');
 const tick=()=>{if(stop||document.hidden||n>=text.length){render(el,text);el.classList.remove('typing');skip=null;stick();done();return}
  n=Math.min(text.length,n+step);render(el,text.slice(0,n));stick();requestAnimationFrame(tick)};
 tick()}
function bubble(role,text){const me=role==='user',row=mk('div','row '+(me?'me':'ai')),msg=mk('div','msg');
 if(!me)row.append(mk('div','av','D'));
 if(me)msg.append(mk('p','',text));row.append(msg);log.append(row);return {row,msg}}
function acts(b,text,last){const a=mk('div','act'),c=mk('button','','نسخ الرد');c.type='button';c.onclick=()=>copy(text,c,'نسخ الرد');a.append(c);
 if('speechSynthesis' in window){const v=mk('button','','🔊');v.type='button';v.title='قراءة بصوت عالٍ';v.onclick=()=>{const ss=speechSynthesis;if(ss.speaking){ss.cancel();return}const u=new SpeechSynthesisUtterance(text.replace(/```[\s\S]*?```/g,' ').replace(/[*_`#>|]/g,''));u.lang='ar-SA';ss.speak(u)};a.append(v)}
 if(last){const r=mk('button','rg','↻ إعادة');r.type='button';r.title='أعد توليد هذا الرد';r.onclick=()=>submit('',true);a.append(r)}
 b.msg.append(a)}
function thinking(){const r=mk('div','row ai'),m=mk('div','msg think');r.append(mk('div','av','D'));
 for(let i=0;i<3;i++)m.append(mk('i'));m.append(mk('span','','يفكّر…'));r.append(m);log.append(r);stick(true);return r}
function err(t,retry){const d=mk('div','err');d.append(mk('span','',t));
 if(retry){const b=mk('button','','إعادة المحاولة');b.type='button';b.onclick=()=>{d.remove();submit(retry)};d.append(b)}log.append(d);stick(true)}
async function api(path,body){try{const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':csrf},body:JSON.stringify(body||{}),credentials:'same-origin'});
 let j={};try{j=await r.json()}catch(e){}if(r.status===401){location.reload()}return {ok:r.ok,j}}
 catch(e){return {ok:false,j:{error:'انقطع الاتصال بالخادم.'}}}}
async function stream(path,body,on){let r;
 try{r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':csrf},body:JSON.stringify(body),credentials:'same-origin'})}
 catch(e){return {ok:false,j:{error:'انقطع الاتصال بالخادم.'}}}
 if(!(r.headers.get('Content-Type')||'').includes('ndjson')||!r.body){let j={};try{j=await r.json()}catch(e){}if(r.status===401)location.reload();return {ok:r.ok,j}}
 const rd=r.body.getReader(),dec=new TextDecoder();let buf='',res={ok:false,j:{error:'انقطع البث قبل اكتمال الرد.'}};
 for(;;){let c;try{c=await rd.read()}catch(e){break}if(c.done)break;buf+=dec.decode(c.value,{stream:true});
  let i;while((i=buf.indexOf('\n'))>=0){const ln=buf.slice(0,i);buf=buf.slice(i+1);if(!ln)continue;let o;try{o=JSON.parse(ln)}catch(e){continue}
   if(o.t!==undefined||o.reset)on(o);else if(o.done)res={ok:true,j:{reply:o.reply}};else if(o.error)res={ok:false,j:{error:o.error}}}}
 return res}
const TIPS=['حلّل سجلّ تنبيه مشبوه وصنّفه وفق MITRE ATT&CK','كيف أؤمّن خادم لينكس خطوة بخطوة؟','اشرح ثغرة SQL Injection بمثال وطرق الوقاية','قارن بين TLS 1.2 وTLS 1.3 في جدول'];
function hint(){log.textContent='';const h=mk('div','hero');h.append(mk('span','orb'),mk('h2','','DARWIN DZ'),mk('p','','مساعدك الذكي للأمن السيبراني والبرمجة. اسأل بما تشاء.'));
 const c=mk('div','chips');TIPS.forEach(t=>{const b=mk('button','chip',t);b.type='button';b.onclick=()=>submit(t);c.append(b)});h.append(c);log.append(h)}
function fit(){box.style.height='auto';box.style.height=Math.min(box.scrollHeight,200)+'px';
 cnt.textContent=box.value.length>MAX*.8?box.value.length+' / '+MAX:''}
function fin(){busy=false;send.disabled=false;box.focus()}
async function submit(text,regen){if(busy)return;busy=true;send.disabled=true;if(skip)skip();
 log.querySelectorAll('.rg').forEach(x=>x.remove());const h=log.querySelector('.hero');if(h)h.remove();
 let old=null;
 if(regen){const rows=log.querySelectorAll('.row.ai'),last=rows[rows.length-1];if(last)last.remove();old=H.pop()}
 else{bubble('user',text);H.push({role:'user',content:text});box.value='';fit()}
 stick(true);
 const w=thinking();let live=null,acc='',pend=false;
 const paint=()=>{pend=false;if(live){render(live.msg,acc);stick()}};
 const on=o=>{if(!live){w.remove();live=bubble('assistant','');live.msg.classList.add('typing')}
  if(o.reset)acc='';else acc+=o.t;if(!pend){pend=true;requestAnimationFrame(paint)}};
 const {ok,j}=await stream(regen?'/api/regenerate':'/api/chat',{msg:text||'',persona:$('#p').value,stream:true},on);w.remove();
 if(ok&&j.reply){H.push({role:'assistant',content:j.reply});
  if(live){live.msg.classList.remove('typing');render(live.msg,j.reply);acts(live,j.reply,true);stick();fin()}
  else{const b=bubble('assistant','');reveal(b.msg,j.reply,()=>{acts(b,j.reply,true);fin()})}}
 else{if(live)live.row.remove();
  if(old){H.push(old);const b=bubble('assistant','');render(b.msg,old.content);acts(b,old.content,true);err(j.error||'تعذّرت إعادة التوليد.')}
  else err(j.error||'تعذّر الإرسال.',text);fin()}}
const init=JSON.parse($('#init').textContent);
if(init.length){H=init.slice();init.forEach((m,i)=>{const b=bubble(m.role,m.content);if(m.role!=='user'){render(b.msg,m.content);acts(b,m.content,i===init.length-1)}});stick(true)}else hint();
form.addEventListener('submit',ev=>{ev.preventDefault();const t=box.value.trim();if(t)submit(t)});
box.addEventListener('input',fit);
box.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey&&!e.isComposing){e.preventDefault();form.requestSubmit()}});
document.addEventListener('keydown',e=>{
 if(e.key==='Escape'){if(!sheet.hidden)closeTools();else if(skip)skip();return}
 const typing=/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
 if(e.key==='/'&&!typing&&!e.ctrlKey&&!e.metaKey){e.preventDefault();box.focus()}
 else if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();$('#new').click()}
 else if(e.altKey&&e.key.toLowerCase()==='t'){e.preventDefault();sheet.hidden?openTools():closeTools()}});
log.addEventListener('click',e=>{if(skip&&!e.target.closest('a,button'))skip()});
$('#new').onclick=async()=>{if(skip)skip();await api('/api/clear');H=[];hint()};
const out=$('#out');if(out)out.onclick=async()=>{await api('/logout');location.reload()};
// tools sheet: the offline helper tools, run on the server, nothing stored
const sheet=$('#sh'),tk=$('#tk'),tq=$('#tq'),ti=$('#ti'),to=$('#to'),TL=JSON.parse($('#tl').textContent);
const fill=q=>{q=(q||'').toLowerCase();tk.textContent='';TL.forEach(([k,l])=>{if(q&&!(l.toLowerCase().includes(q)||k.includes(q)))return;const o=mk('option','',l);o.value=k;tk.append(o)})};fill('');
const openTools=()=>{sheet.hidden=false;ti.focus()},closeTools=()=>{sheet.hidden=true;box.focus()};
$('#tb').onclick=openTools;$('#tx').onclick=closeTools;sheet.addEventListener('click',e=>{if(e.target===sheet)closeTools()});
tq.addEventListener('input',()=>fill(tq.value.trim()));
let tbusy=false;
async function runTool(){if(tbusy||!tk.value)return;tbusy=true;$('#tr').disabled=true;to.classList.remove('bad');to.textContent='…';
 const {ok,j}=await api('/api/tool',{tool:tk.value,text:ti.value});to.textContent=ok?j.output:(j.error||'تعذّر التنفيذ.');to.classList.toggle('bad',!ok);tbusy=false;$('#tr').disabled=false}
$('#tr').onclick=runTool;ti.addEventListener('keydown',e=>{if(e.key==='Enter'&&(e.ctrlKey||e.metaKey)){e.preventDefault();runTool()}});
$('#tc').onclick=function(){copy(to.textContent,this,'نسخ')};
$('#ta').onclick=()=>{const o=to.textContent.trim();if(!o||to.classList.contains('bad'))return;const n=tk.selectedOptions[0]?tk.selectedOptions[0].textContent:'';closeTools();box.value=('اشرح لي هذه النتيجة ('+n+'):\n'+o).slice(0,MAX);fit();box.focus()};
// export the conversation as Markdown
$('#ex').onclick=()=>{if(!H.length)return;const d=new Date(),p=n=>String(n).padStart(2,'0');
 const md=H.map(m=>(m.role==='user'?'## 🧑 أنت':'## 🤖 DARWIN DZ')+'\n\n'+m.content).join('\n\n---\n\n')+'\n';
 const a=mk('a');a.href=URL.createObjectURL(new Blob([md],{type:'text/markdown;charset=utf-8'}));
 a.download='darwin-chat-'+d.getFullYear()+p(d.getMonth()+1)+p(d.getDate())+'-'+p(d.getHours())+p(d.getMinutes())+'.md';
 document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),4000)};
// voice dictation (only where the browser supports it)
const SR=window.SpeechRecognition||window.webkitSpeechRecognition,mic=$('#mic');
if(!SR)mic.remove();else{let rec=null;mic.onclick=()=>{if(rec){rec.stop();return}
 rec=new SR();rec.lang='ar-SA';rec.interimResults=true;rec.continuous=false;const base=box.value;
 rec.onresult=e=>{let t='';for(const r of e.results)t+=r[0].transcript;box.value=((base?base+' ':'')+t).slice(0,MAX);fit()};
 rec.onend=()=>{rec=null;mic.classList.remove('on')};rec.onerror=()=>{};mic.classList.add('on');try{rec.start()}catch(e){rec=null;mic.classList.remove('on')}}}
box.focus();
})();
"""


class ChatSite:
    def __init__(self, app):
        self.app, self.cfg, self.db = app, app.cfg, app.db
        self.sessions: dict = {}
        self.fails: dict = {}
        self.ip_hits: dict = {}
        self.daily = [time.strftime("%Y-%m-%d"), 0]
        self._lock = threading.Lock()
        self.server = None
        self.thread = None

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        site = self
        handler = type("Handler", (_Handler,), {"site": site})
        self.server = LimitedHTTPServer((self.cfg.web_chat_host, self.cfg.web_chat_port), handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.1}, name="web-chat", daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        log.info("Web chat listening on http://%s:%s (%s)", host, port, "public" if self.cfg.web_chat_public else "password")
        if host not in ("127.0.0.1", "::1", "localhost"):
            log.warning("Web chat is reachable beyond this machine over plain HTTP: put HTTPS (reverse proxy) in front of it")

    @property
    def port(self) -> int:
        return self.server.server_address[1] if self.server else 0

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    # ------------------------------------------------------------------ auth
    def check_password(self, value: str) -> bool:
        a, b = (value or "").encode("utf-8"), self.cfg.web_chat_password.encode("utf-8")
        return bool(b) and hmac.compare_digest(a, b)

    def login_blocked(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            xs = [t for t in self.fails.get(ip, []) if now - t < LOGIN_WINDOW]
            self.fails[ip] = xs
            return len(xs) >= LOGIN_FAILS

    def login_failed(self, ip: str) -> None:
        with self._lock:
            now = time.time()
            self.fails.setdefault(ip, []).append(now)
            if len(self.fails) > 1000:
                self.fails = {k: v for k, v in self.fails.items() if v and now - v[-1] < LOGIN_WINDOW}

    def new_session(self, authed: bool) -> tuple:
        sid, now = secrets.token_urlsafe(32), time.time()
        with self._lock:
            self.sessions = {k: v for k, v in self.sessions.items() if v["exp"] > now}
            if len(self.sessions) >= MAX_SESSIONS:                       # cookie-less flood: drop the oldest, never grow without bound
                for k in sorted(self.sessions, key=lambda k: self.sessions[k]["exp"])[:MAX_SESSIONS // 10]:
                    self.sessions.pop(k, None)
            s = {"exp": now + SESSION_TTL, "csrf": secrets.token_urlsafe(24), "authed": authed, "chat": [], "times": [],
                 "busy": False, "persona": "default", "gen": 0}
            self.sessions[sid] = s
        return sid, s

    def session(self, sid: str):
        with self._lock:
            s = self.sessions.get(sid or "")
            if s and s["exp"] > time.time():
                return s
            self.sessions.pop(sid or "", None)
            return None

    def end_session(self, sid: str) -> None:
        with self._lock:
            self.sessions.pop(sid or "", None)

    def host_ok(self, host_header: str) -> bool:
        loopback_bind = self.cfg.web_chat_host in ("127.0.0.1", "::1", "localhost")
        allowed = self.cfg.web_chat_hostnames()
        if not loopback_bind and not allowed:
            return True
        h = (host_header or "").strip().lower()
        bare = h.rsplit(":", 1)[0] if (h.count(":") == 1 or h.startswith("[") and "]:" in h) else h
        return bare in LOOPBACK or bare in allowed or h in allowed

    def ip_allowed(self, ip: str, bucket: str = "chat") -> bool:
        now = time.time()
        rate = IP_RATE if bucket == "chat" else TOOL_IP_RATE
        key = ip if bucket == "chat" else f"{bucket}:{ip}"
        with self._lock:
            hits = [t for t in self.ip_hits.get(key, []) if now - t < rate[1]]
            ok = len(hits) < rate[0]
            if ok:
                hits.append(now)
            self.ip_hits[key] = hits
            if len(self.ip_hits) > 2000:
                self.ip_hits = {k: v for k, v in self.ip_hits.items() if v and now - v[-1] < IP_RATE[1]}
            return ok

    def daily_ok(self) -> bool:
        cap = self.cfg.web_chat_daily
        if cap <= 0:
            return True
        today = time.strftime("%Y-%m-%d")
        with self._lock:
            if self.daily[0] != today:
                self.daily[:] = [today, 0]
            if self.daily[1] >= cap:
                return False
            self.daily[1] += 1
            return True

    # ------------------------------------------------------------------ chat
    def chat(self, sess: dict, persona: str, text: str, ip: str, regen: bool = False, on_delta=None) -> tuple:
        """-> (status, {"reply": ...} | {"error": ...}). Synchronous call to the model (the server is threaded)."""
        text = (text or "").strip()[:MAX_INPUT]
        if not text and not regen:
            return 400, {"error": "اكتب رسالة أولاً."}
        now = time.time()
        with self._lock:
            sess["times"] = [t for t in sess["times"] if now - t < RATE[1]]
            if len(sess["times"]) >= RATE[0]:
                return 429, {"error": "رسائل كثيرة بسرعة. انتظر قليلاً."}
            if sess["busy"]:
                return 409, {"error": "ما زال الرد السابق قيد المعالجة."}
        if not self.ip_allowed(ip):
            return 429, {"error": "طلبات كثيرة من هذا العنوان. انتظر دقيقة."}
        if not self.daily_ok():
            return 429, {"error": "بلغت الدردشة حدّها اليومي. يتجدد غداً."}
        persona = persona if persona in PERSONAS else "default"
        p = PERSONAS[persona]
        system = "\n\n".join(x for x in (CORE_PROMPT if p.get("core") else "", self.cfg.system_prompt, p["prompt"],
                                         SAFETY_TAIL if p.get("core") else "") if x)
        with self._lock:
            if sess["busy"]:                                            # re-check under the same lock that sets it: two parallel requests
                return 409, {"error": "ما زال الرد السابق قيد المعالجة."}   # could both pass the early check and corrupt the history
            base = list(sess["chat"])
            if regen:                                                   # answer the last question again, replacing the last reply
                if len(base) < 2 or base[-1]["role"] != "assistant" or base[-2]["role"] != "user":
                    return 400, {"error": "لا يوجد رد لإعادة توليده."}
                text, base = base[-2]["content"], base[:-2]
            sess["persona"] = persona
            sess["times"].append(now)
            sess["busy"] = True
            gen = sess.get("gen", 0)
            hist = base + [{"role": "user", "content": text}]
        kept, total = [], 0
        for m in reversed(hist[-MAX_MSGS:]):
            total += len(m["content"])
            if total > MAX_CONTEXT_CHARS and kept:
                break
            kept.append(m)
        kept.reverse()
        msgs = ([{"role": "system", "content": system}] if system else []) + kept
        try:
            reply, usage = self.app.ai.chat(msgs, min(1.3, self.cfg.default_temp + (0.25 if regen else 0.0)),
                                            stream=on_delta is not None, on_delta=on_delta)
        except APIError as e:
            return 502, {"error": self.app._err_text("ar", e).replace("<b>", "").replace("</b>", "")}
        except Exception:
            log.exception("web chat failed")
            return 502, {"error": "تعذّر الاتصال بالذكاء الاصطناعي الآن."}
        finally:
            with self._lock:
                sess["busy"] = False
        with self._lock:
            if sess.get("gen", 0) == gen:                               # "new chat" pressed while this answer was in flight: do not resurrect it
                sess["chat"] = (hist + [{"role": "assistant", "content": reply}])[-MAX_MSGS:]
        try:
            self.db.add_usage(next(iter(sorted(self.cfg.admin_ids)), 0), int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0)))
        except Exception:
            log.debug("web chat usage not recorded", exc_info=True)
        return 200, {"reply": reply}

    def tool(self, sess: dict, kind: str, text: str, ip: str) -> tuple:
        """-> (status, {"output": ...} | {"error": ...}). Offline helper tools (the same ones as the web panel); nothing is stored."""
        kind = str(kind or "")[:24]
        if kind not in dict(WEB_TOOLS):
            return 404, {"error": "أداة غير معروفة."}
        now = time.time()
        with self._lock:
            sess["tool_times"] = [t for t in sess.get("tool_times", []) if now - t < TOOL_RATE[1]]
            if len(sess["tool_times"]) >= TOOL_RATE[0]:
                return 429, {"error": "أدوات كثيرة بسرعة. انتظر قليلاً."}
            sess["tool_times"].append(now)
        if not self.ip_allowed(ip, "tool"):
            return 429, {"error": "طلبات كثيرة من هذا العنوان. انتظر دقيقة."}
        try:
            out = run_web_tool(kind, str(text or "")[:MAX_INPUT])
        except ValueError as e:
            return 400, {"error": str(e)[:300] or "مدخل غير صالح."}
        except Exception:
            log.exception("web chat tool failed: %s", kind)
            return 500, {"error": "تعذّر تشغيل الأداة."}
        return 200, {"output": str(out)[:TOOL_OUT_MAX]}

    # ------------------------------------------------------------------ pages
    def login_page(self, error: str = "", nonce: str = "") -> bytes:
        err = f'<div class="flash">{_e(error)}</div>' if error else ""
        body = ('<div class="login"><span class="orb"></span><h1>DARWIN DZ</h1><p class="mut">دردشة الذكاء الاصطناعي</p>' + err +
                '<form method="post" action="/login"><input type="password" name="password" placeholder="كلمة المرور" '
                'autocomplete="current-password" required autofocus><button class="p">دخول</button></form>'
                '<p class="mut">اطلب كلمة المرور من مدير البوت (الأمر <code>/webchat</code>).</p></div>')
        return self._page(body, "دخول — DARWIN DZ")

    def chat_page(self, sess: dict, nonce: str) -> bytes:
        persona = sess.get("persona") if sess.get("persona") in PERSONAS else "default"
        opts = "".join(f'<option value="{_e(k)}"{" selected" if k == persona else ""}>{_e(v["ar"])}</option>' for k, v in PERSONAS.items())
        def _js(obj) -> str:                                            # JSON for a <script type="application/json"> block
            return json.dumps(obj, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
        init, tools = _js(sess["chat"]), _js([[k, v] for k, v in WEB_TOOLS])
        out = '<button id="out" class="btn" type="button" title="خروج">خروج</button>' if not self.cfg.web_chat_public else ""
        body = ('<header><div class="brand"><span class="orb"></span><h1>DARWIN DZ</h1></div>'
                f'<select id="p" aria-label="الشخصية">{opts}</select>'
                '<button id="th" class="btn" type="button" title="المظهر" aria-label="المظهر">◐</button>'
                '<button id="ex" class="btn" type="button" title="تصدير المحادثة (Markdown)" aria-label="تصدير">⤓</button>'
                '<button id="tb" class="btn" type="button" title="الأدوات (Alt+T)">🧰 أدوات</button>'
                f'<button id="new" class="btn" type="button">＋ جديدة</button>{out}</header>'
                '<main id="log" role="log" aria-live="polite"></main>'
                '<div class="dock"><button id="dn" class="btn" type="button" aria-label="إلى الأسفل">↓</button>'
                f'<form id="f"><textarea id="m" rows="1" maxlength="{MAX_INPUT}" placeholder="اكتب رسالتك…" aria-label="الرسالة" required></textarea>'
                '<button id="mic" type="button" title="إملاء صوتي" aria-label="إملاء صوتي">🎙</button>'
                '<button id="s" type="submit" aria-label="إرسال">↑</button></form>'
                '<div class="meta"><span>Enter للإرسال · Shift+Enter سطر جديد</span><span id="cnt"></span></div></div>'
                '<div id="sh" class="sheet" hidden role="dialog" aria-modal="true" aria-label="الأدوات"><div class="panel">'
                '<div class="ph"><b>🧰 أدوات DARWIN</b><button id="tx" class="btn" type="button" aria-label="إغلاق">✕</button></div>'
                '<input id="tq" type="search" placeholder="ابحث عن أداة…" autocomplete="off" aria-label="بحث">'
                '<select id="tk" aria-label="الأداة"></select>'
                f'<textarea id="ti" rows="4" maxlength="{MAX_INPUT}" placeholder="أدخل المدخل هنا — Ctrl+Enter للتنفيذ" aria-label="المدخل"></textarea>'
                '<div class="pb"><button id="tr" class="btn pri" type="button">تنفيذ</button><button id="tc" class="btn" type="button">نسخ</button>'
                '<button id="ta" class="btn" type="button">اسأل الذكاء عن النتيجة</button></div>'
                '<pre id="to" aria-live="polite"></pre></div></div>'
                f'<script type="application/json" id="init">{init}</script>'
                f'<script type="application/json" id="tl">{tools}</script>'
                f'<script nonce="{nonce}">{JS}</script>')
        return self._page(body, "دردشة AI — DARWIN DZ", csrf=sess["csrf"])

    @staticmethod
    def _page(body: str, title: str, csrf: str = "") -> bytes:
        attr = f' data-csrf="{_e(csrf)}"' if csrf else ""
        return (f'<!doctype html><html lang="ar" dir="rtl"{attr}><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="robots" content="noindex">'
                '<meta name="color-scheme" content="dark light"><meta name="theme-color" content="#050506">'
                f'<title>{_e(title)}</title><style>{CSS}</style></head><body>{body}</body></html>').encode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    site: ChatSite = None
    protocol_version = "HTTP/1.1"
    timeout = 15
    server_version = "DZ"
    sys_version = ""

    def log_message(self, fmt, *args):
        log.debug("webchat %s", fmt % args)

    def _https(self) -> bool:
        return (self.headers.get("X-Forwarded-Proto") or "").lower() == "https" or self.site.cfg.web_chat_url.startswith("https://")

    def _send(self, code: int, body: bytes = b"", ctype: str = "text/html; charset=utf-8", headers: dict | None = None, nonce: str = "") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        script = f"script-src 'nonce-{nonce}'; connect-src 'self'; " if nonce else ""
        csp = ("default-src 'none'; style-src 'unsafe-inline'; " + script +
               "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        extra = {"Strict-Transport-Security": "max-age=31536000"} if self._https() else {}
        for k, v in {**SEC, "Content-Security-Policy": csp, **extra, **(headers or {})}.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, obj: dict, headers: dict | None = None) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", headers)

    def _cookie(self) -> str:
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE:
                return v
        return ""

    def _set_cookie(self, sid: str, max_age: int) -> str:
        return f"{COOKIE}={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}" + ("; Secure" if self._https() else "")

    def _ip(self) -> str:
        if self.site.cfg.web_chat_url and self.client_address[0] in ("127.0.0.1", "::1"):     # only a LOCAL proxy may speak for a client
            xff = [x.strip() for x in (self.headers.get("X-Forwarded-For") or "").split(",") if x.strip()]
            if xff:
                return xff[-1][:45]
        return self.client_address[0]

    def _guard(self) -> bool:
        if self.headers.get("Transfer-Encoding") is not None:
            self.close_connection = True
            self._send(501, b"transfer-encoding not supported", "text/plain; charset=utf-8", {"Connection": "close"})
            return False
        if not self.site.host_ok(self.headers.get("Host", "")) and urlsplit(self.path).path != "/healthz":
            self.close_connection = True                        # a POST body would stay unread on the keep-alive connection
            self._send(403, b"forbidden", "text/plain; charset=utf-8", {"Connection": "close"})
            return False
        if self.command == "POST" and cross_site(self.headers):   # browsers flag requests started by another site: never legitimate here
            self.close_connection = True
            self._send(403, b"cross-site request refused", "text/plain; charset=utf-8", {"Connection": "close"})
            return False
        return True

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if n < 0 or n > MAX_BODY:
            return None
        return self.rfile.read(n)

    def _current(self):
        """Session of this visitor. Public mode creates one on first contact; password mode needs a logged-in one."""
        sess = self.site.session(self._cookie())
        if sess and (sess["authed"] or self.site.cfg.web_chat_public):
            return sess, {}
        if self.site.cfg.web_chat_public:
            sid, sess = self.site.new_session(True)
            return sess, {"Set-Cookie": self._set_cookie(sid, SESSION_TTL)}
        return None, {}

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        try:
            if not self._guard():
                return
            path = urlsplit(self.path).path
            if path == "/healthz":
                return self._send(200, b"ok", "text/plain; charset=utf-8")
            if path != "/":
                return self._send(404, b"not found", "text/plain; charset=utf-8")
            sess, hdr = self._current()
            if not sess:
                return self._send(200, self.site.login_page())
            nonce = secrets.token_urlsafe(16)
            self._send(200, self.site.chat_page(sess, nonce), headers=hdr, nonce=nonce)
        except Exception:
            log.exception("web chat GET failed")
            self._send(500, b"server error", "text/plain; charset=utf-8")

    def do_POST(self):
        try:
            if not self._guard():
                return
            path = urlsplit(self.path).path
            raw = self._body()
            if raw is None:
                self.close_connection = True
                return self._send(413, b"too large", "text/plain; charset=utf-8", {"Connection": "close"})
            if path == "/login":
                return self._login(raw)
            sess, _ = self._current()
            if not sess or not hmac.compare_digest((self.headers.get("X-CSRF") or "").encode("utf-8"), sess["csrf"].encode("utf-8")):
                return self._json(401 if not sess else 403, {"error": "انتهت الجلسة. أعد تحميل الصفحة."})
            if path == "/logout":
                self.site.end_session(self._cookie())
                return self._json(200, {"ok": True}, {"Set-Cookie": self._set_cookie("", 0)})
            if path == "/api/clear":
                with self.site._lock:
                    sess["chat"] = []
                    sess["gen"] = sess.get("gen", 0) + 1
                return self._json(200, {"ok": True})
            if path in ("/api/chat", "/api/regenerate", "/api/tool"):
                try:
                    data = json.loads(raw.decode("utf-8") or "{}")
                    if not isinstance(data, dict):
                        raise ValueError
                except ValueError:
                    return self._json(400, {"error": "طلب غير صالح."})
                if path == "/api/tool":
                    code, out = self.site.tool(sess, data.get("tool", ""), data.get("text", ""), self._ip())
                elif data.get("stream") is True:
                    return self._chat_stream(sess, data, regen=path == "/api/regenerate")
                else:
                    code, out = self.site.chat(sess, str(data.get("persona", "")), str(data.get("msg", "")), self._ip(), regen=path == "/api/regenerate")
                return self._json(code, out)
            self._send(404, b"not found", "text/plain; charset=utf-8")
        except Exception:
            log.exception("web chat POST failed")
            self._send(500, b"server error", "text/plain; charset=utf-8")

    def _start_stream(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Connection", "close")                      # the body ends when the connection closes (no Content-Length)
        self.send_header("X-Accel-Buffering", "no")                  # tell nginx-style proxies not to hold the stream back
        for k, v in {**SEC, "Content-Security-Policy": "default-src 'none'"}.items():
            self.send_header(k, v)
        self.end_headers()

    def _chat_stream(self, sess: dict, data: dict, regen: bool) -> None:
        """Live answer as newline-delimited JSON: {"t": new text} ... then {"done": true, "reply": full} or {"error": ...}.

        Anything that fails before the first token (bad input, rate limit, busy) is still an ordinary JSON error response."""
        st = {"started": False, "sent": "", "dead": False}

        def emit(obj: dict) -> None:
            if st["dead"]:
                return
            try:
                self.wfile.write((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))
                self.wfile.flush()
            except OSError:                                          # the browser went away: keep the model call and history consistent
                st["dead"] = True

        def on_delta(full: str) -> None:
            try:
                if not st["started"]:
                    st["started"] = True
                    self._start_stream()
                if not full.startswith(st["sent"]):                  # the client library retried and restarted the answer
                    emit({"reset": True})
                    st["sent"] = ""
                if len(full) > len(st["sent"]):
                    emit({"t": full[len(st["sent"]):]})
                    st["sent"] = full
            except OSError:
                st["dead"] = True

        code, out = self.site.chat(sess, str(data.get("persona", "")), str(data.get("msg", "")), self._ip(), regen=regen, on_delta=on_delta)
        if not st["started"]:
            return self._json(code, out)
        emit({"done": True, "reply": out["reply"]} if code == 200 else {"error": out.get("error", "تعذّر الإرسال.")})
        self.close_connection = True

    def _login(self, raw: bytes) -> None:
        site = self.site
        if site.cfg.web_chat_public:
            return self._send(303, b"", headers={"Location": "/"})
        ip = self._ip()
        if site.login_blocked(ip):
            return self._send(429, site.login_page("محاولات كثيرة. انتظر بضع دقائق."), headers={"Retry-After": "300"})
        pw = (parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True, max_num_fields=10).get("password") or [""])[0]
        if not site.check_password(pw):
            site.login_failed(ip)
            site.db.add_audit(0, "webchat_login_fail", ip[:45])
            return self._send(401, site.login_page("كلمة المرور غير صحيحة."))
        sid, _ = site.new_session(True)
        site.db.add_audit(0, "webchat_login", ip[:45])
        self._send(303, b"", headers={"Location": "/", "Set-Cookie": self._set_cookie(sid, SESSION_TTL)})
