var $=function(i){return document.getElementById(i)},S={users:[],inbounds:[],settings:{}},TAB=localStorage.tab||'dash',Q='',SYS=null,H={rx:[],tx:[]},T1,T2;
var GB=1073741824,THEMES=[['knight','Dark Knight','linear-gradient(135deg,#5b9bff,#04060a)'],['gotham','Gotham','linear-gradient(135deg,#aab8cc,#0a0b0d)'],['joker','Joker','linear-gradient(135deg,#b57bff,#6dffa0)']];
var IC={dash:'<path d="M3 13h8V3H3zM13 21h8V11h-8zM13 3v6h8V3zM3 21h8v-6H3z"/>',users:'<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6M16 4.5a3.5 3.5 0 010 7M18 14c2.2.6 3.5 2.4 3.5 6"/>',
 inb:'<path d="M12 3v12m0 0l-4-4m4 4l4-4M4 17v3h16v-3"/>',scan:'<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12l6-6"/>',
 set:'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z"/>'};
var TABS=[['dash','داشبورد'],['users','کاربران'],['inb','اینباندها'],['scan','اسکنر'],['set','تنظیمات']];
function toast(t){var e=$('toast');e.textContent=t;e.className='s';setTimeout(function(){e.className=''},1600)}
function esc(s){return String(s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function B(n){if(n==null)return'—';var u=['B','KB','MB','GB','TB'],i=0;while(n>=1024&&i<4){n/=1024;i++}return n.toFixed(i>1?2:0)+' '+u[i]}
function Dur(s){s=Math.floor(s);var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return(d?d+'d ':'')+h+'h '+m+'m'}
function api(m,u,b){return fetch(u,{method:m,headers:{'content-type':'application/json'},body:b?JSON.stringify(b):undefined,credentials:'same-origin'}).then(function(r){
 if(r.status==401){gate(0);throw 0}return r.json().then(function(d){if(!r.ok&&d.e&&d.e!==1){toast(d.e);throw d}return d})})}
function cp(t,m){(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).catch(function(){var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove()});toast(m||'کپی شد')}
var AD=function(){return S.settings&&S.settings.addr?'?addr='+encodeURIComponent(S.settings.addr):''};
function subUrl(id){return location.origin+'/sub/'+id+AD()}
/* ---------- fx & charts ---------- */
var FX={on:false};
function city(){var c=$('city');if(c.firstChild)return;var s='',x=0,h,i;while(x<400){var w=9+Math.random()*20;h=22+Math.random()*58;s+='<rect x="'+x+'" y="'+(100-h)+'" width="'+w+'" height="'+h+'"/>';
 for(i=0;i<3;i++)if(Math.random()>.6)s+='<rect class="w" x="'+(x+2+Math.random()*(w-6))+'" y="'+(100-h+4+Math.random()*(h-12))+'" width="1.6" height="1.8"/>';x+=w+.8}c.innerHTML=s}
function loginFx(on){
 if(on&&!FX.on){FX.on=true;city();var cv=$('rain'),cx=cv.getContext('2d'),rgb=(getComputedStyle(document.documentElement).getPropertyValue('--rgb')||'91,155,255').trim();
  var sz=function(){cv.width=innerWidth;cv.height=innerHeight};sz();window.onresize=sz;FX.d=[];for(var i=0;i<140;i++)FX.d.push({x:Math.random()*innerWidth,y:Math.random()*innerHeight,l:10+Math.random()*18,v:9+Math.random()*9});
  (function loop(){if(!FX.on)return;cx.clearRect(0,0,cv.width,cv.height);cx.strokeStyle='rgba('+rgb+',.35)';cx.lineWidth=1;cx.beginPath();
   FX.d.forEach(function(d){cx.moveTo(d.x,d.y);cx.lineTo(d.x-d.l*.18,d.y+d.l);d.y+=d.v;d.x-=d.v*.18;if(d.y>cv.height){d.y=-20;d.x=Math.random()*cv.width+40}});cx.stroke();FX.r=requestAnimationFrame(loop)})();
  FX.t=setInterval(function(){var l=$('login'),f=function(ms){l.classList.add('fl');setTimeout(function(){l.classList.remove('fl')},ms)};f(110);setTimeout(function(){f(80)},230)},11000)}
 else if(!on&&FX.on){FX.on=false;cancelAnimationFrame(FX.r);clearInterval(FX.t)}}
function bars(a,h,cls){var mx=Math.max.apply(null,a.concat([1])),n=a.length,w=100/n;return '<svg class="'+cls+'" viewBox="0 0 100 '+h+'" preserveAspectRatio="none">'+a.map(function(v,i){var bh=Math.max(v?1.5:.7,v/mx*(h-2));
 return '<rect x="'+(i*w+w*.14).toFixed(2)+'" y="'+(h-bh).toFixed(2)+'" width="'+(w*.72).toFixed(2)+'" height="'+bh.toFixed(2)+'" fill="'+(i==n-1?'var(--ac3)':'var(--ac)')+'" fill-opacity="'+(v?(i==n-1?1:.6):.14)+'"/>'}).join('')+'</svg>'}
/* ---------- gate ---------- */
function gate(p){loginFx(!p);$('login').className=p?'hide':'';$('panel').className=p?'wrap':'hide';$('dock').className=p?'dock':'dock hide';clearInterval(T1);clearInterval(T2);
 if(p){dock();loadState();sys();T1=setInterval(sys,3000);T2=setInterval(function(){if(TAB=='users'||TAB=='dash')loadState(1)},15000)}}
$('lf').onsubmit=function(e){e.preventDefault();$('err').textContent='';
 fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({pass:$('pw').value})}).then(function(r){
  if(r.ok){$('pw').value='';var l=$('login');l.classList.add('go');setTimeout(function(){l.classList.remove('go');gate(1)},750)}else r.json().then(function(d){$('err').textContent=d.e||'رمز اشتباهه'})})};
function dock(){$('dock').innerHTML=TABS.map(function(t){return '<button data-t="'+t[0]+'" class="'+(t[0]==TAB?'on':'')+'"><svg viewBox="0 0 24 24">'+IC[t[0]]+'</svg>'+t[1]+'</button>'}).join('')}
$('dock').onclick=function(e){var b=e.target.closest('button');if(!b)return;TAB=b.dataset.t;localStorage.tab=TAB;dock();render();window.scrollTo(0,0)};
function loadState(quiet){return api('GET','/api/state'+AD()).then(function(d){S=d;if(!quiet||TAB!='users'||!document.querySelector('.ov:not(.hide)'))render()})}
/* ---------- sys ---------- */
function bar(id,p){var e=$(id);if(!e)return;e.style.width=Math.min(100,Math.max(1,p))+'%';e.className=p>90?'d':p>75?'w':''}
function put(id,v){var e=$(id);if(e)e.textContent=v}
function spark(a,c){if(a.length<2)return'';var mx=Math.max.apply(null,a.concat([1])),w=300,h=60,p=a.map(function(v,i){return(i/(a.length-1)*w).toFixed(1)+','+(h-3-v/mx*(h-8)).toFixed(1)}).join(' ');
 return '<svg class="sp-l" viewBox="0 0 300 60" preserveAspectRatio="none"><polyline points="0,60 '+p+' 300,60" fill="'+c+'" fill-opacity=".12" stroke="none"/><polyline points="'+p+'" fill="none" stroke="'+c+'" stroke-width="1.8" vector-effect="non-scaling-stroke"/></svg>'}
function sys(){api('GET','/api/sys').then(function(s){SYS=s;H.rx.push(s.net.rxs);H.tx.push(s.net.txs);if(H.rx.length>40){H.rx.shift();H.tx.shift()}
 $('xp').className='pill '+(s.xray.on?'ok':'bad');$('xp').lastChild.textContent=s.xray.on?'XRAY ONLINE':'XRAY OFFLINE';
 if(TAB!='dash')return;
 bar('cpuB',s.cpu);put('cpuT',s.cpu.toFixed(1)+'%  ·  '+s.cores+' vCPU');
 bar('ramB',s.mem.used/s.mem.total*100);put('ramT',B(s.mem.used)+' / '+B(s.mem.total));
 if(s.disk){bar('dskB',s.disk.used/s.disk.total*100);put('dskT',B(s.disk.used)+' / '+B(s.disk.total))}
 put('rx',B(s.net.rxs)+'/s');put('tx',B(s.net.txs)+'/s');put('up',Dur(s.pup));put('cn',s.conns);put('xm',B(s.xray.mem));put('rg',s.region);put('cn2',s.conns);
 if($('spk'))$('spk').innerHTML=spark(H.rx,'#5b9bff')+spark(H.tx,'#4fd1a0')})}
/* ---------- views ---------- */
function render(){var v=$('view');({dash:vDash,users:vUsers,inb:vInb,scan:vScan,set:vSet})[TAB](v)}
function vDash(v){var act=S.users.filter(function(u){return u.status=='active'}).length;
 v.innerHTML='<div class="sg"><div class="sc"><small>USERS</small><b>'+S.users.length+'</b></div><div class="sc"><small>ACTIVE</small><b>'+act+'</b></div>'+
 '<div class="sc"><small>TRAFFIC</small><b>'+B(S.totalUsed)+'</b></div><div class="sc"><small>CONNECTIONS</small><b id="cn2">'+(SYS?SYS.conns:'—')+'</b></div></div>'+
 trafficCard()+'<div class="g2"><div class="card"><h3><span>Server</span><span id="rg" style="letter-spacing:1px"></span></h3>'+
 '<div class="m"><div class="t"><span>CPU</span><b id="cpuT">—</b></div><div class="bar"><i id="cpuB"></i></div></div>'+
 '<div class="m"><div class="t"><span>RAM</span><b id="ramT">—</b></div><div class="bar"><i id="ramB"></i></div></div>'+
 '<div class="m"><div class="t"><span>Disk</span><b id="dskT">—</b></div><div class="bar"><i id="dskB"></i></div></div>'+
 '<div class="kv"><div><small>UPTIME</small><b id="up">—</b></div><div><small>XRAY RAM</small><b id="xm">—</b></div></div></div>'+
 '<div class="card"><h3><span>Network</span></h3><div class="kv" style="margin:0 0 8px"><div><small>DOWN ↓</small><b id="rx">—</b></div><div><small>UP ↑</small><b id="tx">—</b></div></div><div id="spk"></div></div></div>';
 v.insertAdjacentHTML('beforeend',topCard());if(SYS){sys()}}
function trafficCard(){var d=S.daily,sum=d.total.reduce(function(a,b){return a+b},0);return '<div class="card" style="margin-bottom:14px"><h3><span>Traffic · 14 days</span></h3><div class="big"><b>'+B(sum)+'</b><span>امروز: '+B(d.total[d.total.length-1])+'</span></div>'+bars(d.total,60,'chart')+'<div class="axis"><span>'+d.dates[0].slice(5)+'</span><span>'+d.dates[d.dates.length-1].slice(5)+'</span></div></div>'}
function topCard(){var l=S.users.slice().sort(function(a,b){return b.used-a.used}).slice(0,5),mx=Math.max.apply(null,l.map(function(u){return u.used}).concat([1]));
 return '<div class="card" style="margin-top:14px"><h3><span>Top users</span></h3>'+(l.length?l.map(function(u){return '<div class="t5"><span class="n">'+esc(u.name)+'</span><div class="bar"><i style="width:'+Math.max(2,u.used/mx*100)+'%"></i></div><span class="s">'+B(u.used)+'</span></div>'}).join(''):'<div class="empty">—</div>')+'</div>'}
function uCard(u){var pct=u.limit?Math.min(100,u.used/u.limit*100):0,st={active:'فعال',off:'غیرفعال',expired:'منقضی',limited:'حجم تمام'}[u.status],
 cls=u.status=='active'?'ok':u.status=='off'?'':'bad',rem=u.exp?(u.exp>Date.now()?Math.ceil((u.exp-Date.now())/864e5)+' روز مانده':'منقضی شده'):'نامحدود';
 return '<div class="card u'+(u.status=='active'?'':' d')+'"><div class="h"><b>'+esc(u.name)+'</b><span class="pill '+cls+'"><i></i>'+st+'</span></div>'+
 '<div class="ub"><i class="'+(pct>90?'d':pct>75?'w':'')+'" style="width:'+(u.limit?Math.max(2,pct):100)+'%;'+(u.limit?'':'opacity:.25')+'"></i></div>'+
 '<div class="um"><span><b>'+B(u.used)+'</b> / '+(u.limit?B(u.limit):'∞')+'</span><span>'+rem+'</span></div>'+'<div class="um" style="margin:0"><span>۱۴ روز اخیر</span><span>امروز: <b>'+B(u.days[u.days.length-1])+'</b></span></div>'+bars(u.days,24,'mini')+(u.note?'<div class="note">'+esc(u.note)+'</div>':'')+
 '<div class="chips">'+u.links.map(function(l){return '<span class="chip" data-a="cfg" data-i="'+u.id+'" data-k="'+l.k+'">'+esc(l.n)+'</span>'}).join('')+'</div>'+
 '<div class="ac"><button class="sm p" data-a="sub" data-i="'+u.id+'">لینک اشتراک</button><button class="sm" data-a="pg" data-i="'+u.id+'">صفحه</button><button class="sm" data-a="ed" data-i="'+u.id+'">ویرایش</button></div></div>'}
function vUsers(v){v.innerHTML='<div class="sec"><h2>کاربران</h2><span class="pill">'+S.users.length+'</span></div><div class="tbar"><input id="q" placeholder="جستجو..." value="'+esc(Q)+'"><button class="btn" id="nu">+ جدید</button></div><div class="ug" id="ul"></div>';
 $('nu').onclick=newUser;$('q').oninput=function(){Q=this.value;ulist()};ulist()}
function ulist(){var l=S.users.filter(function(u){return u.name.toLowerCase().indexOf(Q.toLowerCase())>=0});$('ul').innerHTML=l.length?l.map(uCard).join(''):'<div class="empty" style="grid-column:1/-1">کاربری پیدا نشد</div>'}
document.addEventListener('click',function(e){var b=e.target.closest('#ul [data-a]');if(!b)return;var i=b.dataset.i,a=b.dataset.a,u=S.users.filter(function(x){return x.id==i})[0];
 if(a=='cfg'){var l=u.links.filter(function(x){return x.k==b.dataset.k})[0];cp(l.l,l.n+' کپی شد')}
 if(a=='sub'){cp(subUrl(i),'لینک اشتراک کپی شد');qrModal(u)}
 if(a=='pg')window.open(subUrl(i),'_blank');
 if(a=='ed')editUser(u)});
/* ---------- modals ---------- */
function modal(title,html){$('md').innerHTML='<div class="card sheet"><h3><span>'+title+'</span><button class="x2" id="mx">×</button></h3>'+html+'</div>';$('md').className='ov';$('mx').onclick=closeM}
function closeM(){$('md').className='ov hide'}
$('md').onclick=function(e){if(e.target==$('md'))closeM()};
function qrModal(u){var s=subUrl(u.id);modal(esc(u.name),'<div style="text-align:center"><img src="/qr?d='+encodeURIComponent(s)+'" width="220" height="220" style="border-radius:14px;background:#fff;padding:6px" alt=""><div class="lk">'+esc(s)+'</div></div><div class="ac"><button class="sm p" id="mc">کپی</button><button class="sm" id="mo">باز کردن صفحه</button></div>');
 $('mc').onclick=function(){cp(s)};$('mo').onclick=function(){window.open(s,'_blank')}}
function newUser(){modal('کاربر جدید','<span class="lab">نام</span><input id="f1"><div class="row2"><div><span class="lab">حجم (GB) — 0 نامحدود</span><input id="f2" type="number" min="0" step="any" value="0"></div><div><span class="lab">مدت (روز) — 0 نامحدود</span><input id="f3" type="number" min="0" value="30"></div></div><span class="lab">یادداشت</span><input id="f4"><button class="btn" id="ok">ساخت کاربر</button>');
 $('ok').onclick=function(){api('POST','/api/users',{name:$('f1').value,gb:+$('f2').value,days:+$('f3').value,note:$('f4').value}).then(function(){closeM();toast('کاربر ساخته شد');loadState()})}}
function editUser(u){var d=u.exp?new Date(u.exp).toISOString().slice(0,10):'';
 modal('ویرایش · '+esc(u.name),'<span class="lab">نام</span><input id="f1" value="'+esc(u.name)+'"><div class="row2"><div><span class="lab">حجم (GB)</span><input id="f2" type="number" min="0" step="any" value="'+(u.limit?+(u.limit/GB).toFixed(2):0)+'"></div><div><span class="lab">انقضا</span><input id="f3" type="date" value="'+d+'"></div></div><span class="lab">یادداشت</span><input id="f4" value="'+esc(u.note||'')+'">'+
 '<div class="ib" style="border:0;padding:4px 0 14px"><div class="g"><b>فعال</b></div><div class="sw'+(u.on?' on':'')+'" id="f5"></div></div><button class="btn" id="ok">ذخیره</button>'+
 '<div class="ac" style="margin-top:10px"><button class="sm" id="rs">ریست ترافیک</button><button class="sm x" id="dl">حذف کاربر</button></div>');
 $('f5').onclick=function(){this.classList.toggle('on')};
 $('ok').onclick=function(){var v=$('f3').value;api('POST','/api/user/update',{id:u.id,name:$('f1').value,gb:+$('f2').value,exp:v?new Date(v+'T23:59:59').getTime():0,note:$('f4').value,on:$('f5').classList.contains('on')}).then(function(){closeM();toast('ذخیره شد');loadState()})};
 $('rs').onclick=function(){api('POST','/api/user/update',{id:u.id,reset:1}).then(function(){closeM();toast('ترافیک صفر شد');loadState()})};
 $('dl').onclick=function(){if(confirm('حذف شود؟'))api('POST','/api/user/del',{id:u.id}).then(function(){closeM();loadState()})}}
/* ---------- inbounds ---------- */
function vInb(v){v.innerHTML='<div class="sec"><h2>اینباندها</h2><button class="sm p" id="ni">+ جدید</button></div><div class="card" id="il"></div><p class="hint2" style="margin-top:12px">همه اینباندها روی همون پورت ۴۴۳ دامنه کار می‌کنن و با مسیر (Path) از هم جدا می‌شن. gRPC و Reality روی Railway پشتیبانی نمی‌شن.</p>';
 $('il').innerHTML=S.inbounds.map(function(i){return '<div class="ib"><div class="g"><b>'+esc(i.name)+'</b><small>'+i.proto+' · '+i.net+' · '+esc(i.path)+'</small></div><div class="sw'+(i.on?' on':'')+'" data-t="'+i.id+'"></div><button class="sm x" data-d="'+i.id+'">حذف</button></div>'}).join('');
 $('il').onclick=function(e){var t=e.target.closest('[data-t]'),d=e.target.closest('[data-d]');
  if(t){var i=S.inbounds.filter(function(x){return x.id==t.dataset.t})[0];api('POST','/api/inbound/update',{id:i.id,on:!i.on}).then(function(){loadState()})}
  if(d&&confirm('حذف شود؟'))api('POST','/api/inbound/del',{id:d.dataset.d}).then(function(){loadState()})};
 $('ni').onclick=function(){var rp='/'+Math.random().toString(36).slice(2,8);
  modal('اینباند جدید','<span class="lab">نام</span><input id="f1" placeholder="مثلاً VLESS · Fast"><div class="row2"><div><span class="lab">پروتکل</span><select id="f2"><option>vless</option><option>vmess</option><option>trojan</option></select></div><div><span class="lab">ترنسپورت</span><select id="f3"><option value="ws">WebSocket</option><option value="httpupgrade">HTTPUpgrade</option></select></div></div><span class="lab">مسیر (Path)</span><input id="f4" value="'+rp+'" style="direction:ltr;text-align:left"><button class="btn" id="ok">ساخت</button>');
  $('ok').onclick=function(){api('POST','/api/inbounds',{name:$('f1').value,proto:$('f2').value,net:$('f3').value,path:$('f4').value}).then(function(){closeM();toast('ساخته شد');loadState()})}}}
/* ---------- scanner ---------- */
function vScan(v){v.innerHTML='<div class="sec"><h2>اسکنر کلین‌آی‌پی</h2></div><div class="card"><p class="hint2">چند آی‌پی تصادفی از رنج‌های CDN تست می‌شه و سریع‌ترین‌ها نشون داده می‌شن. پینگ از سمت سرور اندازه‌گیری می‌شه؛ آی‌پی‌ها رو بعداً توی کلاینتت هم امتحان کن.</p>'+
 '<span class="lab">SNI</span><input id="sn" value="speed.cloudflare.com" style="direction:ltr;text-align:left"><span class="lab">تعداد آی‌پی</span><select id="sc"><option>40</option><option selected>80</option><option>150</option></select><button class="btn" id="go">شروع اسکن</button></div><div class="card" id="rs" style="margin-top:14px;display:none"></div>';
 $('go').onclick=function(){var b=this;b.innerHTML='<span class="spin"></span>در حال اسکن...';b.disabled=true;
  api('POST','/api/scan',{sni:$('sn').value,count:+$('sc').value}).then(function(r){b.textContent='شروع اسکن';b.disabled=false;var el=$('rs');el.style.display='block';
   el.innerHTML='<h3><span>Results</span><span>'+r.ok+' / '+r.tested+'</span></h3>'+(r.list.length?r.list.map(function(x){return '<div class="res"><code>'+x.ip+'</code><span class="ms '+(x.ms<250?'g':x.ms<600?'y':'r')+'">'+x.ms+' ms</span><span style="display:flex;gap:6px"><button class="sm" data-c="'+x.ip+'">کپی</button><button class="sm p" data-u="'+x.ip+'">استفاده</button></span></div>'}).join(''):'<div class="empty">آی‌پی سالمی پیدا نشد</div>');
   el.onclick=function(e){var c=e.target.closest('[data-c]'),u=e.target.closest('[data-u]');if(c)cp(c.dataset.c);if(u)api('POST','/api/settings',{addr:u.dataset.u}).then(function(){toast('آدرس پیش‌فرض ست شد');loadState(1)})}}).catch(function(){b.textContent='شروع اسکن';b.disabled=false})}}
/* ---------- settings ---------- */
function vSet(v){v.innerHTML='<div class="sec"><h2>تنظیمات</h2></div><div class="g2"><div class="card"><h3><span>آدرس پیش‌فرض کانفیگ‌ها</span></h3><p class="hint2">اگه کلین‌آی‌پی بذاری، توی همه لینک‌ها و اشتراک‌ها به‌جای دامنه استفاده می‌شه. خالی = خود دامنه.</p><input id="ad" value="'+esc(S.settings.addr||'')+'" placeholder="مثلاً 104.16.x.x" style="direction:ltr;text-align:left"><button class="btn" id="sa">ذخیره</button></div>'+
 '<div class="card"><h3><span>رمز پنل</span></h3><input id="np" type="password" placeholder="رمز جدید (حداقل ۶ کاراکتر)"><button class="btn" id="sp">تغییر رمز</button></div></div>'+
 '<div class="card" style="margin-top:14px"><h3><span>Theme</span></h3><div class="thg">'+THEMES.map(function(t){return '<div class="th'+(S.settings.theme==t[0]?' on':'')+'" data-th="'+t[0]+'"><i style="background:'+t[2]+'"></i>'+t[1]+'</div>'}).join('')+'</div></div>'+
 '<div class="card" style="margin-top:14px"><h3><span>Update · GitHub</span><span id="uv" style="letter-spacing:1px;direction:ltr">'+(S.version.sha?S.version.sha.slice(0,7):'—')+' · '+S.version.src+'</span></h3>'+
 '<div class="hint2" id="ui">ریپو و برنچ رو بذار؛ هر وقت چیزی توی گیت‌هاب پوش کردی، از همین‌جا بدون ری‌دیپلوی نصب می‌شه.</div>'+
 '<input id="ur" placeholder="owner/repo" value="'+esc(S.settings.repo||'')+'" style="direction:ltr;text-align:left"><div class="row2"><input id="ub" placeholder="branch" value="'+esc(S.settings.branch||'main')+'" style="direction:ltr;text-align:left"><input id="ut" type="password" placeholder="'+(S.settings.hasToken?'توکن ذخیره شده':'Token (ریپو خصوصی)')+'" style="direction:ltr;text-align:left"></div>'+
 '<div class="ib" style="border:0;padding:2px 0 12px"><div class="g"><b>آپدیت خودکار</b><small style="direction:rtl;text-align:right">هر ۳۰ دقیقه چک و نصب می‌شه</small></div><div class="sw'+(S.settings.auto?' on':'')+'" id="ua"></div></div>'+
 '<div class="ac"><button class="sm" id="us">ذخیره</button><button class="sm" id="uc">بررسی</button><button class="sm p" id="ug">آپدیت</button></div></div>'+
 '<div class="card" style="margin-top:14px"><h3><span>About</span></h3><div class="kv"><div><small>HOST</small><b>'+esc(S.host)+'</b></div><div><small>VERSION</small><b>BATAMN 4.0</b></div></div><button class="ghost" id="lo" style="margin-top:14px;width:100%">خروج از پنل</button></div>';
 document.querySelector('.thg').onclick=function(e){var t=e.target.closest('[data-th]');if(!t)return;document.documentElement.dataset.theme=t.dataset.th;S.settings.theme=t.dataset.th;api('POST','/api/settings',{theme:t.dataset.th}).then(function(){toast('تم عوض شد');render()})};
 $('ua').onclick=function(){this.classList.toggle('on')};
 var usv=function(){return api('POST','/api/settings',{repo:$('ur').value,branch:$('ub').value,token:$('ut').value,auto:$('ua').classList.contains('on')})};
 $('us').onclick=function(){usv().then(function(){$('ut').value='';toast('ذخیره شد');loadState(1)})};
 $('uc').onclick=function(){var b=this;b.innerHTML='<span class="spin"></span>';usv().then(function(){return api('GET','/api/update/check')}).then(function(r){
   $('ui').innerHTML=(r.available?'<b style="color:var(--ok)">آپدیت جدید موجوده</b>':'<b>نسخه‌ات به‌روزه</b>')+'<br><span style="direction:ltr;display:inline-block">'+r.latest.sha.slice(0,7)+' · '+esc(r.latest.msg)+'</span>';
   b.textContent='بررسی'}).catch(function(){b.textContent='بررسی'})};
 $('ug').onclick=function(){if(!confirm('آپدیت از گیت‌هاب نصب بشه؟ پنل چند ثانیه ری‌استارت می‌شه.'))return;var b=this;b.innerHTML='<span class="spin"></span>';
  usv().then(function(){return api('POST','/api/update/apply')}).then(function(r){toast('نصب شد؛ در حال ری‌استارت...');var n=0,t=setInterval(function(){n++;fetch('/api/me').then(function(x){if(x.ok){clearInterval(t);location.reload()}}).catch(function(){});if(n>40){clearInterval(t);location.reload()}},2000)}).catch(function(){b.textContent='آپدیت'})};
 $('sa').onclick=function(){api('POST','/api/settings',{addr:$('ad').value}).then(function(){toast('ذخیره شد');loadState(1)})};
 $('sp').onclick=function(){api('POST','/api/settings',{pass:$('np').value}).then(function(){$('np').value='';toast('رمز عوض شد')})};
 $('lo').onclick=function(){fetch('/api/logout',{method:'POST'}).then(function(){gate(0)})}}
fetch('/api/me').then(function(r){gate(r.ok?1:0)});
