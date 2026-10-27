// BATAMN v3 — Xray panel: users (traffic/expiry), inbounds, scanner, settings — single HTTP port
process.on('uncaughtException',e=>console.log('[fatal-guard] uncaughtException:',e&&e.stack||e));
process.on('unhandledRejection',e=>console.log('[fatal-guard] unhandledRejection:',e&&e.stack||e));
const http=require('http'),net=require('net'),tls=require('tls'),fs=require('fs'),os=require('os'),path=require('path'),crypto=require('crypto'),{spawn,execFile}=require('child_process');
let qrlib=null;try{qrlib=require('qrcode-generator')}catch(e){console.log('qr disabled')}
const PORT=process.env.PORT||8080;
let DIR=process.env.BATAMN_DATA||process.env.DATA_DIR||'/data';
try{fs.mkdirSync(DIR,{recursive:true});fs.accessSync(DIR,fs.constants.W_OK)}catch(e){DIR=path.join(__dirname,'data');fs.mkdirSync(DIR,{recursive:true})}
const DBF=path.join(DIR,'db.json'),OLD=path.join(DIR,'users.json');
const GB=1073741824,GHAPI=process.env.GITHUB_API||'https://api.github.com';

// ---------- db ----------
const DEF_IN=[
 {name:'VLESS · WS',proto:'vless',net:'ws',path:'/ws'},{name:'VMess · WS',proto:'vmess',net:'ws',path:'/vm'},
 {name:'Trojan · WS',proto:'trojan',net:'ws',path:'/tr'},{name:'VLESS · HTTPUpgrade',proto:'vless',net:'httpupgrade',path:'/hu'}];
// NODE mode: this process is a worker node (another Railway project) that syncs users from a master panel
const NODE_MODE=process.env.NODE_MODE==='1'&&!!process.env.MASTER_URL&&!!process.env.NODE_TOKEN;
let NODE_PEND={},nodeErr='';
let db;
if(NODE_MODE)db={secret:'node',settings:{addr:'',theme:'gotham',pass:crypto.randomBytes(16).toString('hex')},inbounds:[],users:[],locs:[],nodes:[]};
else try{db=readDb()}catch(e){
  let old=[];try{old=JSON.parse(fs.readFileSync(OLD))}catch(_){}
  db={secret:crypto.randomBytes(24).toString('hex'),settings:{addr:'',theme:'gotham',pass:process.env.ADMIN_PASS||'admin'},
    inbounds:DEF_IN.map((x,i)=>({id:'i'+(i+1),port:10000+i,on:true,...x})),
    users:old.length?old.map(u=>({limit:0,exp:0,used:0,note:'',...u})):[{id:crypto.randomUUID(),name:'default',on:true,created:Date.now(),limit:0,exp:0,used:0,note:''}]};
  save();
}
if(db.settings.theme!=='gotham'){db.settings.theme='gotham';try{save()}catch(e){}}
function save(){if(NODE_MODE)return;const tmp=DBF+'.tmp';fs.writeFileSync(tmp,JSON.stringify(db,null,1));
  try{if(fs.existsSync(DBF))fs.copyFileSync(DBF,DBF+'.bak')}catch(e){}
  fs.renameSync(tmp,DBF)}
function readDb(){for(const f of [DBF,DBF+'.bak']){try{const d=JSON.parse(fs.readFileSync(f,'utf8'));if(d&&Array.isArray(d.users)&&d.settings)return d}catch(e){}}
  try{if(fs.existsSync(DBF)){const c=DBF+'.corrupt-'+Date.now();fs.renameSync(DBF,c);console.log('[db] db.json unreadable, kept as',c)}}catch(e){}
  throw new Error('no db')}
db.nodes=db.nodes||[];
const F=n=>fs.readFileSync(path.join(__dirname,n));
const STATIC={'/':['index.html','text/html; charset=utf-8'],'/style.css':['style.css','text/css'],'/app.js':['app.js','application/javascript'],'/bg.svg':['bg.svg','image/svg+xml'],'/speed.js':['speed.js','application/javascript']};
const FILES={};for(const k in STATIC)FILES[k]=F(STATIC[k][0]);
const SUB=F('sub.html').toString();
// fonts come from npm packages installed at build time and are served same-origin (works behind filtering)
const NM=[process.env.NODE_PATH,path.join(__dirname,'node_modules'),'/app/node_modules'].filter(Boolean);
const FONTSRC={'vazir.woff2':['vazirmatn/fonts/webfonts',/\[wght\].*\.woff2$|variable.*\.woff2$/i,/Regular\.woff2$/i],
 'inter.woff2':['@fontsource-variable/inter/files',/^inter-latin-wght-normal\.woff2$/],'mono.woff2':['@fontsource-variable/jetbrains-mono/files',/^jetbrains-mono-latin-wght-normal\.woff2$/]};
const fontCache={};
function fontFile(n){if(n in fontCache)return fontCache[n];const d=FONTSRC[n];let out=null;
  if(d)for(const b of NM){try{const dir=path.join(b,d[0]),l=fs.readdirSync(dir);for(const rx of d.slice(1)){const m=l.find(x=>rx.test(x));if(m){out=path.join(dir,m);break}}}catch(e){}if(out)break}
  return fontCache[n]=out}
let CF=[];try{CF=fs.readFileSync(path.join(__dirname,'assets/cf_subnets.txt'),'utf8').split('\n').map(s=>s.trim()).filter(Boolean)}catch(e){}

// ---------- daily stats ----------
const dayKey=(t=Date.now())=>new Date(t).toISOString().slice(0,10);
const dates14=()=>{const a=[];for(let i=13;i>=0;i--)a.push(dayKey(Date.now()-i*864e5));return a};
function addTraffic(u,d){const k=dayKey();u.days=u.days||{};u.days[k]=(u.days[k]||0)+d;db.daily=db.daily||{};db.daily[k]=(db.daily[k]||0)+d}
function prune(){const cut=dayKey(Date.now()-35*864e5);for(const o of [db.daily||{},...db.users.map(u=>u.days||{})])for(const k in o)if(k<cut)delete o[k]}
// ---------- user state ----------
const expired=u=>u.exp>0&&Date.now()>u.exp, limited=u=>u.limit>0&&u.used>=u.limit;
const status=u=>!u.on?'off':expired(u)?'expired':limited(u)?'limited':'active';
const isActive=u=>status(u)==='active';
const sig=()=>JSON.stringify([db.users.filter(isActive).map(u=>u.id),db.inbounds.filter(i=>i.on).map(i=>[i.id,i.proto,i.net,i.path,i.port,i.egress||'']),(db.locs||[]).filter(l=>l.on).map(l=>[l.id,l.host,l.port,l.user||'',l.pass||'',l.proto||'socks5']),[...blocks.keys()]]);
const locOn=()=>(db.locs||[]).filter(l=>l.on&&l.host&&+l.port>0&&+l.port<65536);
const locTag=id=>'loc-'+id;
const locProto=l=>(l.proto==='http')?'http':'socks5';
function locOutbounds(){return locOn().map(l=>{const s={address:l.host,port:+l.port};if(l.user)s.users=[{user:l.user,pass:l.pass||''}];
  if(locProto(l)==='http')return{tag:locTag(l.id),protocol:'http',settings:{servers:[s]}};
  return{tag:locTag(l.id),protocol:'socks',settings:{servers:[s]}}})}
function locRules(){const ok=new Set(locOn().map(l=>l.id));return db.inbounds.filter(i=>i.on&&i.egress&&ok.has(i.egress)).map(i=>({type:'field',inboundTag:[i.id],outboundTag:locTag(i.egress)}))}

// ---------- online tracking (xray access log) + device limit ----------
const ACC=path.join(DIR,'access.log'),WIN=120000;
const online=new Map(),blocks=new Map();let accPos=0,ipSeen=0;
try{fs.writeFileSync(ACC,'')}catch(e){}
function ipKey(ip){ip=ip.replace(/^\[|\]$/g,'').replace(/^::ffff:/,'');
  if(ip.includes(':')){const[h,t]=ip.split('::'),a=h?h.split(':'):[],b=t?t.split(':'):[];if(ip.includes('::'))while(a.length+b.length<8)a.push('0');
    const f=a.concat(b).map(x=>parseInt(x||'0',16).toString(16)).slice(0,4);return{key:f.join(':'),rule:f.join(':')+'::/64'}}
  return{key:ip,rule:ip}}
function seen(uid,ip){const k=ipKey(ip),now=Date.now();let m=online.get(uid);if(!m)online.set(uid,m=new Map());const e=m.get(k.key);if(e)e.last=now;else m.set(k.key,{ip:k.key,rule:k.rule,first:now,last:now})}
const onlineOf=uid=>{const m=online.get(uid),now=Date.now();return m?[...m.values()].filter(e=>now-e.last<WIN):[]};
function parseAcc(txt){for(const line of txt.split('\n')){const m=/ from (?:tcp:|udp:)?(.+):\d+ accepted .* email: (\S+)\s*$/.exec(line);if(!m)continue;
  const ip=m[1].replace(/^\[|\]$/g,'');if(ip==='127.0.0.1'||ip==='::1')continue;ipSeen=Date.now();seen(m[2],ip)}}
function tailAcc(){fs.stat(ACC,(e,st)=>{if(e)return;if(st.size<accPos)accPos=0;
  const now=Date.now();for(const[uid,m]of online){for(const[k,v]of m)if(now-v.last>WIN*2)m.delete(k);if(!m.size)online.delete(uid)}
  if(st.size===accPos)return;
  try{const len=Math.min(st.size-accPos,2e6),fd=fs.openSync(ACC,'r'),buf=Buffer.alloc(len);fs.readSync(fd,buf,0,len,accPos);fs.closeSync(fd);
    const txt=buf.toString('utf8'),nl=txt.lastIndexOf('\n');if(nl<0){if(len>=2e6)accPos+=len;return}
    accPos+=Buffer.byteLength(txt.slice(0,nl+1));parseAcc(txt.slice(0,nl));
    if(accPos>8e6){try{fs.truncateSync(ACC,0);accPos=0}catch(_){}}}catch(_){}})}
function enforce(){const now=Date.now();let ch=false;
  for(const[k,b]of blocks)if(b.exp<now){blocks.delete(k);ch=true}
  for(const u of db.users){if(!u.maxDev||!isActive(u))continue;
    onlineOf(u.id).sort((a,b)=>a.first-b.first).slice(u.maxDev).forEach(e=>{const k=u.id+'|'+e.rule;if(!blocks.has(k)){blocks.set(k,{uid:u.id,rule:e.rule,exp:now+180000});ch=true}})}
  if(ch)restartSoon()}
const blockRules=()=>[...blocks.values()].map(b=>({type:'field',user:[b.uid],source:[b.rule],outboundTag:'block'}));
function onlineSummary(){let devs=0,us=0;const per={},list=[];
  for(const u of db.users){const o=onlineOf(u.id);if(o.length){us++;devs+=o.length;per[u.id]=o.length;list.push({id:u.id,name:u.name,ips:o.map(e=>e.ip),max:u.maxDev||0})}}
  return{users:us,devices:devs,per,list:list.slice(0,30),track:Date.now()-ipSeen<600000}}
setInterval(()=>{const n=Date.now();for(const k in fails)if(n-fails[k].t>600000)delete fails[k];for(const k in sshF)if(n-sshF[k].t>600000)delete sshF[k];for(const k in spQ)if(n-spQ[k].t>120000)delete spQ[k]},300000);
setInterval(tailAcc,3000);setInterval(enforce,10000);

// ---------- xray ----------
let xray=null,lastSig='',rt=null,xrayErr='',xrayLog=[],xrayStarts=[];
function buildCfg(){
  const act=db.users.filter(isActive),cl=act.length?act:[{id:crypto.randomUUID()}];
  const inb=db.inbounds.filter(i=>i.on).map(i=>{
    const settings=i.proto==='vless'?{clients:cl.map(u=>({id:u.id,email:u.id})),decryption:'none'}
      :i.proto==='vmess'?{clients:cl.map(u=>({id:u.id,alterId:0,email:u.id}))}
      :{clients:cl.map(u=>({password:u.id,email:u.id}))};
    const ss={network:i.net};ss[i.net==='ws'?'wsSettings':'httpupgradeSettings']={path:i.path};
    return{tag:i.id,listen:'127.0.0.1',port:i.port,protocol:i.proto,settings,streamSettings:ss,sniffing:{enabled:false}};
  });
  inb.push({tag:'api',listen:'127.0.0.1',port:10085,protocol:'dokodemo-door',settings:{address:'127.0.0.1'}});
  return{log:{loglevel:'warning',access:ACC},api:{tag:'api',services:['StatsService']},stats:{},
    dns:{servers:['1.1.1.1','8.8.8.8'],queryStrategy:'UseIPv4'},
    policy:{levels:{0:{handshake:4,connIdle:300,statsUserUplink:true,statsUserDownlink:true}}},
    routing:{rules:[{type:'field',inboundTag:['api'],outboundTag:'api'},...blockRules(),{type:'field',domain:['full:localhost','domain:railway.internal','domain:internal','domain:local'],outboundTag:'block'},{type:'field',ip:['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','::1/128','fc00::/7','fe80::/10'],outboundTag:'block'},...locRules()]},
    inbounds:inb,outbounds:[{protocol:'freedom',settings:{domainStrategy:'UseIPv4'}},...locOutbounds(),{protocol:'blackhole',tag:'block'}]};
}
function startXray(force){
  const now=Date.now();xrayStarts=xrayStarts.filter(t=>now-t<60000);xrayStarts.push(now);
  if(xrayStarts.length>8&&!force){xrayErr='کرش پشت سر هم — چند لحظه صبر کن یا ری‌استارت دستی بزن';return}
  (async()=>{
    lastSig=sig();let cfg;try{cfg=buildCfg()}catch(e){xrayErr='ساخت کانفیگ ناموفق: '+String(e.message||e).slice(0,200);return}
    const f=path.join(DIR,'config.json'),nf=path.join(DIR,'config.new.json');
    try{fs.writeFileSync(nf,JSON.stringify(cfg))}catch(e){xrayErr='نوشتن کانفیگ ناموفق';return}
    const bad=await new Promise(r=>{execFile('xray',['run','-test','-c',nf],{timeout:20000},(e,o,er)=>{r(e?String(er||e.message||e).split('\n').slice(0,4).join(' ').slice(0,300):null)})});
    if(bad){xrayErr='کانفیگ رد شد، قبلی نگه داشته شد: '+bad;try{fs.renameSync(nf,f+'.bad')}catch(e){}return}
    try{fs.renameSync(nf,f)}catch(e){}
    xrayErr='';
    if(xray){xray.removeAllListeners('exit');xray.removeAllListeners('error');try{xray.kill()}catch(e){}}
    try{xray=spawn('xray',['run','-c',f],{stdio:['ignore','pipe','pipe']})}
    catch(e){xrayErr='اجرای xray ناموفق: '+e.message;return}
    xray.stdout.on('data',d=>xlog(d));xray.stderr.on('data',d=>xlog(d));
    xray.on('error',e=>{xrayErr='اجرای xray ناموفق: '+e.message});
    xray.on('exit',(c,s)=>{xlog('exit code='+c+' sig='+s);setTimeout(()=>startXray(),3000)});
  })();
}
function xlog(s){try{const ls=String(s).split('\n').map(t=>t.trim()).filter(Boolean).slice(-6);
  for(const t of ls){xrayLog.push(t.slice(0,300));if(/error|failed|panic|fatal|cannot|invalid/i.test(t))xrayErr=t.slice(0,200)}
  if(xrayLog.length>80)xrayLog.splice(0,xrayLog.length-80)}catch(e){}}
function restartSoon(){clearTimeout(rt);rt=setTimeout(async()=>{await poll();startXray()},400)}
function poll(){return new Promise(r=>{
  execFile('xray',['api','statsquery','-s','127.0.0.1:10085','-pattern','user>>>','-reset'],{timeout:5000},(e,out)=>{
    if(e||!out)return r();
    try{let ch=false;(JSON.parse(out).stat||[]).forEach(s=>{const m=/^user>>>(.+)>>>traffic>>>(uplink|downlink)$/.exec(s.name);if(!m)return;
      const u=db.users.find(x=>x.id===m[1]);if(u){const d=+s.value||0;u.used+=d;addTraffic(u,d);ch=true;if(NODE_MODE)NODE_PEND[u.id]=(NODE_PEND[u.id]||0)+d}});if(ch){prune();save()}}catch(_){}
    r()})})}
setInterval(async()=>{await poll();if(sig()!==lastSig)startXray()},10000);
startXray();

// ---------- github updater ----------
const E=process.env;
const repoCfg=()=>({repo:db.settings.repo||(E.RAILWAY_GIT_REPO_OWNER&&E.RAILWAY_GIT_REPO_NAME?E.RAILWAY_GIT_REPO_OWNER+'/'+E.RAILWAY_GIT_REPO_NAME:'')||E.GITHUB_REPO||'',branch:db.settings.branch||E.RAILWAY_GIT_BRANCH||'main'});
function curVersion(){
  if(E.BATAMN_OVERLAY==='1'){try{return{...JSON.parse(fs.readFileSync(path.join(__dirname,'INSTALL_META.json'))),src:'panel'}}catch(e){}}
  return{sha:E.RAILWAY_GIT_COMMIT_SHA||'',msg:(E.RAILWAY_GIT_COMMIT_MESSAGE||'').split('\n')[0],src:'image'};
}
const gh=(u,accept)=>fetch(u,{headers:{'User-Agent':'BATAMN','Accept':accept||'application/vnd.github+json',...(db.settings.token?{Authorization:'Bearer '+db.settings.token}:{})},redirect:'follow',signal:AbortSignal.timeout(40000)});
async function latest(){
  const c=repoCfg();if(!c.repo)throw new Error('ریپو GitHub تنظیم نشده');
  const r=await gh(GHAPI+'/repos/'+c.repo+'/commits/'+encodeURI(c.branch));
  if(!r.ok)throw new Error('GitHub '+r.status+(r.status===404?' (ریپو/برنچ پیدا نشد یا خصوصیه و توکن لازمه)':''));
  const j=await r.json();return{sha:j.sha,msg:String(j.commit.message||'').split('\n')[0].slice(0,120),date:j.commit.committer&&j.commit.committer.date};
}
const ex=(c,a)=>new Promise((res,rej)=>execFile(c,a,{timeout:60000},(e,o,er)=>e?rej(new Error((er||e.message).toString().slice(0,200))):res(o)));
const REQ=['server.js','app.js','index.html','style.css','sub.html','bg.svg','assets/cf_subnets.txt'];
let updating=false,lastApply=0;
async function applyUpdate(){
  if(updating)throw new Error('آپدیت در حال انجامه');updating=true;
  try{
    const c=repoCfg(),L=await latest(),tmp=path.join(DIR,'upd'),nd=path.join(DIR,'app.new'),ov=path.join(DIR,'app'),old=path.join(DIR,'app.old');
    for(const p of[tmp,nd,old])fs.rmSync(p,{recursive:true,force:true});fs.mkdirSync(tmp,{recursive:true});fs.mkdirSync(nd,{recursive:true});
    const r=await gh(GHAPI+'/repos/'+c.repo+'/tarball/'+L.sha);if(!r.ok)throw new Error('دانلود ناموفق: '+r.status);
    fs.writeFileSync(path.join(tmp,'src.tgz'),Buffer.from(await r.arrayBuffer()));
    await ex('tar',['-xzf',path.join(tmp,'src.tgz'),'--strip-components=1','-C',nd]);
    let root=nd;if(!fs.existsSync(path.join(nd,'server.js'))){const sub=fs.readdirSync(nd).map(n=>path.join(nd,n)).find(p=>fs.statSync(p).isDirectory()&&fs.existsSync(path.join(p,'server.js')));if(sub)root=sub}
    for(const f of REQ)if(!fs.existsSync(path.join(root,f)))throw new Error('فایل '+f+' توی ریپو نیست');
    await ex(process.execPath,['--check',path.join(root,'server.js')]);await ex(process.execPath,['--check',path.join(root,'app.js')]);
    fs.writeFileSync(path.join(root,'INSTALL_META.json'),JSON.stringify({...L,time:Date.now()}));
    fs.writeFileSync(path.join(root,'INSTALL_TS'),String(Math.floor(Date.now()/1000)));
    if(fs.existsSync(ov))fs.renameSync(ov,old);fs.renameSync(root,ov);
    for(const p of[tmp,nd,old])fs.rmSync(p,{recursive:true,force:true});
    lastApply=Date.now();return L;
  }finally{updating=false}
}
function restartApp(){setTimeout(()=>{if(xray){xray.removeAllListeners('exit');xray.kill()}process.exit(42)},600)}
process.on('exit',()=>{try{xray&&xray.kill()}catch(e){}});
setInterval(async()=>{if(!db.settings.auto||updating||Date.now()-lastApply<600000)return;
  try{const L=await latest(),cur=curVersion();if(L.sha!==cur.sha){console.log('[update] installing',L.sha.slice(0,7));await applyUpdate();restartApp()}}catch(e){console.log('[update]',e.message)}},30*60*1000);

// ---------- auto clean-IP rotation ----------
let lastScan=0;
setInterval(async()=>{
  if(!db.settings.scanAuto||!CF.length)return;
  const everyH=Math.max(1,Math.min(72,+db.settings.scanEveryH||12));
  if(Date.now()-lastScan<everyH*3600e3)return;lastScan=Date.now();
  try{const r=await scan('speed.cloudflare.com',60);
    if(r.list.length&&r.list[0].ip!==db.settings.addr){db.settings.addr=r.list[0].ip;save();console.log('[scan-auto] addr ->',r.list[0].ip,r.list[0].ms+'ms')}}
  catch(e){console.log('[scan-auto]',e.message)}
},10*60*1000);

// ---------- telegram bot (minimal: /start <id-prefix> shows user status) ----------
let botOff=0,botBusy=false;
async function botCall(m,args){const r=await fetch('https://api.telegram.org/bot'+db.settings.botToken+'/'+m,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(args),signal:AbortSignal.timeout(20000)});return r.json()}
setInterval(async()=>{
  if(!db.settings.botToken||botBusy)return;botBusy=true;
  try{
    const u=await botCall('getUpdates',{offset:botOff,timeout:0,allowed_updates:['message']});
    if(u.ok)for(const x of u.result||[]){botOff=x.update_id+1;
      const msg=x.message||{};const txt=String(msg.text||'').trim();const cid=msg.chat&&msg.chat.id;
      if(!cid||!txt.startsWith('/start'))continue;
      const q=txt.split(/\s+/)[1]||'';
      const user=db.users.find(v=>v.id===q||v.id.startsWith(q));
      const t=user?('اشتراک '+user.name+'\nوضعیت: '+status(user)+'\nمصرف: '+Math.round(user.used/1048576)+'MB / '+(user.limit?Math.round(user.limit/1073741824)+'GB':'∞')+(user.exp?'\nانقضا: '+new Date(user.exp).toLocaleDateString('fa-IR'):'')):'سلام! آیدی اشتراکت رو بعد از /start بفرست.\nمثال: /start a1b2c3d4';
      await botCall('sendMessage',{chat_id:cid,text:t}).catch(()=>{});
    }
  }catch(e){}botBusy=false;
},6000);

// ---------- links ----------
const cleanAddr=a=>a&&/^[\w.\-:\[\]]{1,100}$/.test(a)?a:'';
const stripEmoji=s=>String(s==null?'':s).replace(/[\u{1F300}-\u{1FAFF}\u{1F1E6}-\u{1F1FF}\u{2600}-\u{27BF}\u{2B50}\u{2B06}\u{2B55}\u{231A}\u{231B}\u{23E9}-\u{23FA}\u{FE0F}\u{200D}]/gu,'');
const cleanLoc=s=>stripEmoji(s).replace(/[\u0000-\u001F\u007F<>"']/g,'').replace(/\s{2,}/g,' ').trim().slice(0,24);
// extra query parameters appended to every vless/trojan link (e.g. Hiddify fragment, ech=...)
const cleanExtra=v=>{v=String(v==null?'':v).trim().replace(/^[?&]+/,'').replace(/&+$/,'');return /^[A-Za-z0-9_.,:=&%\-+\/]{0,300}$/.test(v)?v:null};
const linkExtra=()=>cleanExtra(db.settings.linkExtra)||'';
// ---------- config names: only the location (flag + country name), no brand, no protocol ----------
const keepName=s=>String(s==null?'':s).replace(/[\u0000-\u001F\u007F<>"']/g,'').replace(/\s{2,}/g,' ').trim().slice(0,40);
const flagOf=cc=>{try{return String.fromCodePoint(cc.charCodeAt(0)+127397,cc.charCodeAt(1)+127397)}catch(e){return''}};
const regionEn=cc=>{try{return new Intl.DisplayNames(['en'],{type:'region'}).of(cc)||''}catch(e){return''}};
// Unicode "fonts" for config names (letters only; flags, digits fallbacks and non-latin text stay as typed)
const STYLE_OFFS={bold:[0x1D5D4,0x1D5EE,0x1D7EC],script:[0x1D4D0,0x1D4EA,null],mono:[0x1D670,0x1D68A,0x1D7F6],double:[0x1D538,0x1D552,0x1D7D8]};
const DBL_EXC={C:'\u2102',H:'\u210D',N:'\u2115',P:'\u2119',Q:'\u211A',R:'\u211D',Z:'\u2124'};
const SMALLCAPS='\u1D00\u0299\u1D04\u1D05\u1D07\uA730\u0262\u029C\u026A\u1D0A\u1D0B\u029F\u1D0D\u0274\u1D0F\u1D18\u01EB\u0280\uA731\u1D1B\u1D1C\u1D20\u1D21x\u028F\u1D22';
const NAME_STYLES=['bold','smallcaps','script','double','mono','plain'];
function styleText(t,st){st=st||db.settings.nameStyle||'bold';t=String(t||'');if(st==='plain'||!NAME_STYLES.includes(st))return t;
  let out='';for(const ch of t){const c=ch.charCodeAt(0);let r=ch;
    if(st==='smallcaps'){if(c>=97&&c<=122)r=SMALLCAPS[c-97];else if(c>=65&&c<=90)r=SMALLCAPS[c-65]}
    else{const o=STYLE_OFFS[st];
      if(c>=65&&c<=90){r=(st==='double'&&DBL_EXC[ch])?DBL_EXC[ch]:String.fromCodePoint(o[0]+c-65)}
      else if(c>=97&&c<=122)r=String.fromCodePoint(o[1]+c-97);
      else if(c>=48&&c<=57&&o[2])r=String.fromCodePoint(o[2]+c-48)}
    out+=r}
  return out}
const locText=(cc,fb)=>{cc=String(cc||'').toUpperCase();return /^[A-Z]{2}$/.test(cc)?(flagOf(cc)+' '+(regionEn(cc)||fb||cc)):(fb||'')};
let SRV_CC='';
async function detectServerCC(){
  try{const r=await fetch('https://www.cloudflare.com/cdn-cgi/trace',{signal:AbortSignal.timeout(8000)});const m=/^loc=([A-Z]{2})/m.exec(await r.text());if(m)SRV_CC=m[1]}catch(e){}
  if(!SRV_CC){const rg=String(process.env.RAILWAY_REPLICA_REGION||process.env.RAILWAY_REGION||'');const map={'europe-west4':'NL','us-west2':'US','us-east4':'US','asia-southeast1':'SG'};for(const k in map)if(rg.startsWith(k)){SRV_CC=map[k];break}}}
detectServerCC();setInterval(detectServerCC,3600e3);
const autoLoc=()=>keepName(db.settings.locName)||locText(SRV_CC,'');
const nodeBase=n=>keepName(n.label)||locText(n.cc,'')||keepName(n.name)||'Node';
function linksFor(u,h,addr){
  const items=[],ibs=db.inbounds.filter(i=>i.on);
  ibs.forEach(i=>{
    const egL=(db.locs||[]).find(x=>x.id===i.egress&&x.on);
    const auto=egL&&[egL.label,egL.country,egL.host].some(v=>v&&cleanLoc(v)===cleanLoc(i.loc));   // loc auto-filled from the proxy label is not a manual name
    let n=(!auto&&keepName(i.loc))||'';
    if(!n&&egL)n=/^[A-Z]{2}$/.test(egL.cc||'')?locText(egL.cc,egL.country):keepName(egL.label||egL.host);
    if(!n)n=autoLoc()||stripEmoji(i.name).replace(/\s*·\s*/g,'-')||'Server';
    items.push({i,host:h,a:addr||db.settings.addr||h,base:n,loc:cleanLoc(i.loc),eg:egL?(egL.label||(egL.host+':'+egL.port)):'',k:i.id});
  });
  // worker nodes: same users, own domain + own location name (proxy-egress inbounds exist only on the master)
  if(!NODE_MODE)(db.nodes||[]).filter(n=>n.on&&n.domain).forEach(n=>{
    const use=ibs.filter(i=>!i.egress),base=nodeBase(n);
    (n.all?use:use.slice(0,1)).forEach(i=>items.push({i,host:n.domain,a:n.domain,base,loc:cleanLoc(base),eg:'',k:i.id+'@'+n.id}));
  });
  const cnt={};
  return items.map(it=>{
    const i=it.i,host=it.host,a=it.a,q='security=tls&sni='+host+'&fp=chrome&alpn=http%2F1.1&host='+host,p=encodeURIComponent(i.path);
    cnt[it.base]=(cnt[it.base]||0)+1;const nm=styleText(cnt[it.base]>1?it.base+' '+cnt[it.base]:it.base);
    let l;
    if(i.proto==='vmess')l='vmess://'+Buffer.from(JSON.stringify({v:'2',ps:nm,add:a,port:'443',id:u.id,aid:'0',scy:'auto',net:i.net,type:'none',host:host,path:i.path,tls:'tls',sni:host,alpn:'http/1.1',fp:'chrome'})).toString('base64');
    else if(i.proto==='trojan')l='trojan://'+u.id+'@'+a+':443?'+q+'&type='+i.net+'&path='+p+'#'+encodeURIComponent(nm);
    else l='vless://'+u.id+'@'+a+':443?encryption=none&'+q+'&type='+i.net+'&path='+p+'#'+encodeURIComponent(nm);
    if(i.proto!=='vmess'){const xp=linkExtra();if(xp)l=l.replace('#','&'+xp+'#')}
    return{k:it.k,n:i.name,loc:it.loc,eg:it.eg,l};
  });
}
// ---------- info "configs" shown at the top of the subscription (usage / plan / days left); they are dummies, not real tunnels ----------
const subInfoOn=()=>db.settings.subInfo!==false;
const gbTxt=n=>{const g=n/1073741824;return (g>=10?g.toFixed(0):Number(g.toFixed(2)).toString())+' GB'};
const fmtUsed=n=>{n=+n||0;if(n<1048576)return '0 MB';const u=['B','KB','MB','GB','TB'];let i=0;while(n>=1024&&i<4){n/=1024;i++}return (i>=3?n.toFixed(2):n.toFixed(0))+' '+u[i]};
function infoLinks(x,st){
  const T=[],days=x.exp?Math.ceil((x.exp-Date.now())/864e5):null,plan=(x.exp&&x.created)?Math.max(1,Math.round((x.exp-x.created)/864e5)):null,c=contact();
  if(st==='active'){
    T.push('📦 '+(x.limit?gbTxt(x.limit):'Unlimited')+' · '+(plan?plan+' Days':'No Expiry'));
    T.push('📊 Used '+fmtUsed(x.used)+(x.limit?' · Left '+gbTxt(Math.max(0,x.limit-x.used)):''));
    T.push('⏳ '+(days==null?'Unlimited Time':Math.max(0,days)+' Days Left'));
    if(x.maxDev)T.push('👥 Devices '+onlineOf(x.id).length+'/'+x.maxDev);
  }else{
    T.push(st==='expired'?'⛔ Expired':st==='limited'?'⛔ Data Finished':'⛔ Disabled');
    T.push('📊 Used '+fmtUsed(x.used)+(x.limit?' / '+gbTxt(x.limit):''));
    if(c.support)T.push('💬 Support @'+c.support);
  }
  return T.map(t=>'vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?encryption=none&security=none&type=tcp#'+encodeURIComponent(styleText(t)));
}
const QC=new Map();
function qrSvg(t){const k=String(t);if(QC.has(k))return QC.get(k);const v=qrSvg0(k);if(QC.size>400)QC.delete(QC.keys().next().value);QC.set(k,v);return v}
const RL={};
const rate=(ip,k,max,ms)=>{const key=k+'|'+ip,n=Date.now(),r=RL[key]||(RL[key]={n:0,t:n});if(n-r.t>(ms||60000)){r.n=0;r.t=n}return ++r.n<=max};
setInterval(()=>{const n=Date.now();for(const k in RL)if(n-RL[k].t>180000)delete RL[k]},120000);
function qrSvg0(t){
  if(!qrlib)return '';
  try{const q=qrlib(0,'M');q.addData(t);q.make();const n=q.getModuleCount(),m=2;let d='';
    for(let r=0;r<n;r++)for(let c=0;c<n;c++)if(q.isDark(r,c))d+='M'+(c+m)+' '+(r+m)+'h1v1h-1z';
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 '+(n+2*m)+' '+(n+2*m)+'" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/><path d="'+d+'" fill="#05070b"/></svg>';
  }catch(e){return ''}
}

// ---------- system stats ----------
const rd=f=>{try{return fs.readFileSync(f,'utf8').trim()}catch(e){return null}};
let cpuPct=0,cpuCores=os.cpus().length,pCg=null,pHost=null,NS={rx:0,tx:0,rxs:0,txs:0,t:0};
function sample(){
  const now=Date.now(),mx=rd('/sys/fs/cgroup/cpu.max'),st=rd('/sys/fs/cgroup/cpu.stat');
  cpuCores=os.cpus().length;
  if(mx){const[q,p]=mx.split(' ');if(q!=='max')cpuCores=Math.max(.1,q/p)}
  const m=st&&/usage_usec (\d+)/.exec(st);
  if(m){const us=+m[1];if(pCg)cpuPct=Math.min(100,Math.max(0,(us-pCg.us)/((now-pCg.t)*1000)/cpuCores*100));pCg={us,t:now}}
  else{let idle=0,tot=0;os.cpus().forEach(c=>{for(const k in c.times)tot+=c.times[k];idle+=c.times.idle});
    if(pHost&&tot>pHost.tot)cpuPct=100-(idle-pHost.idle)/(tot-pHost.tot)*100;pHost={idle,tot}}
  const nd=rd('/proc/net/dev');
  if(nd){let rx=0,tx=0;nd.split('\n').slice(2).forEach(l=>{const[i,v]=l.split(':');if(!v||i.trim()==='lo')return;const a=v.trim().split(/\s+/);rx+=+a[0];tx+=+a[8]});
    if(NS.t){const dt=(now-NS.t)/1000;NS.rxs=Math.max(0,(rx-NS.rx)/dt);NS.txs=Math.max(0,(tx-NS.tx)/dt)}
    NS.rx=rx;NS.tx=tx;NS.t=now}
}
sample();setInterval(sample,2000);
function memInfo(){
  let total=os.totalmem(),used=total-os.freemem();
  let lim=rd('/sys/fs/cgroup/memory.max'),cur=rd('/sys/fs/cgroup/memory.current');
  if(cur==null){lim=rd('/sys/fs/cgroup/memory/memory.limit_in_bytes');cur=rd('/sys/fs/cgroup/memory/memory.usage_in_bytes')}
  if(cur!=null){used=+cur;if(lim&&lim!=='max'&&+lim<total)total=+lim}
  return{total,used:Math.min(used,total)};
}
function diskInfo(){try{const s=fs.statfsSync(DIR);const total=s.bsize*s.blocks;return{total,used:total-s.bsize*s.bavail}}catch(e){return null}}
function xrayMem(){try{const m=/VmRSS:\s+(\d+)/.exec(rd('/proc/'+xray.pid+'/status'));return m?+m[1]*1024:null}catch(e){return null}}
let conns=0;

// ---------- scanner ----------
const ipInt=s=>s.split('.').reduce((a,b)=>a*256+ +b,0),intIp=n=>[n>>>24,n>>>16&255,n>>>8&255,n&255].join('.');
function randIp(){const[ip,m]=CF[Math.floor(Math.random()*CF.length)].split('/'),host=Math.pow(2,32-m);return intIp(ipInt(ip)+1+Math.floor(Math.random()*Math.max(1,host-2)))}
const probe=(ip,sni,to=2500)=>new Promise(res=>{const t0=Date.now();let d=false;const fin=v=>{if(!d){d=true;res(v)}};
  const s=tls.connect({host:ip,port:443,servername:sni,rejectUnauthorized:false,timeout:to},()=>{const ms=Date.now()-t0;s.destroy();fin(ms)});
  s.on('error',()=>fin(null));s.on('timeout',()=>{s.destroy();fin(null)})});
async function scan(sni,count){
  const ips=new Set();while(ips.size<count)ips.add(randIp());const q=[...ips],out=[];
  await Promise.all(Array.from({length:40},async()=>{while(q.length){const ip=q.pop(),ms=await probe(ip,sni);if(ms!=null)out.push({ip,ms})}}));
  return{tested:count,ok:out.length,list:out.sort((a,b)=>a.ms-b.ms).slice(0,24)};
}

// ---------- socks locations (multi-location egress) ----------
const DEFAULT_SOURCES=['https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt','https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt','https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt','https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt','https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/socks5/data.txt'];
const srcList=()=>Array.isArray(db.settings.sources)&&db.settings.sources.length?db.settings.sources:DEFAULT_SOURCES;
function socksConn(host,port,user,pass,th,tp,to=8000){return new Promise(res=>{
  const t0=Date.now();
  let done=false,st=0,buf=Buffer.alloc(0),s=null,triedAlt=false;
  const fin=(sock,ms,why)=>{if(done)return;done=true;clearTimeout(timer);if(!sock){try{s&&s.destroy()}catch(e){}}res({sock,ms,why})};
  const timer=setTimeout(()=>fin(null,null,'timeout'),to);
  const fail=w=>fin(null,null,w);
  const sendReq=pN=>{
    buf=Buffer.alloc(0);
    const hostB=Buffer.from(String(th));
    try{s.write(Buffer.concat([Buffer.from([0x05,0x01,0x00,0x03,hostB.length]),hostB,Buffer.from([(pN>>8)&255,pN&255])]))}
    catch(e){fail('conn')}
  };
  try{s=net.connect({host,port:+port,timeout:to})}catch(e){fail('conn');return}
  s.on('timeout',()=>fail('timeout'));
  s.on('error',e=>fail(e&&e.code==='ENOTFOUND'?'dns':(e&&e.code==='ECONNREFUSED'?'refused':'conn')));
  s.on('connect',()=>{try{s.write(Buffer.from([0x05,0x01,user?0x02:0x00]))}catch(e){fail('conn')}});
  s.on('data',d=>{
    buf=Buffer.concat([buf,d]);
    if(st===0&&buf.length>=2){
      if(buf[0]!==0x05){fail('proto');return}
      if(buf[1]===0xFF){fail('auth');return}
      if(buf[1]===0x02){
        const u=Buffer.from(user||''),p=Buffer.from(pass||'');
        st=1;buf=Buffer.alloc(0);
        try{s.write(Buffer.concat([Buffer.from([0x01,u.length]),u,Buffer.from([p.length]),p]))}catch(e){fail('conn')}
        return;
      }
      st=2;sendReq(tp);return;
    }
    if(st===1&&buf.length>=2){
      if(buf[1]!==0x00){fail('auth');return}
      st=2;sendReq(tp);return;
    }
    if(st===2&&buf.length>=2){
      if(buf[1]===0x00){fin(s,Date.now()-t0,null);return}
      if(!triedAlt){triedAlt=true;sendReq(tp===443?80:443);return}
      fail('denied');
    }
  });
})}
// ---- end-to-end proxy probe: dial a DOMAIN through the proxy, do a REAL verified TLS handshake and fetch Cloudflare's trace ----
// (a proxy that only answers the handshake, resolves no domains, or tampers with TLS fails here)
const E2E_HOST=process.env.E2E_HOST||'www.cloudflare.com',E2E_INSECURE=process.env.E2E_INSECURE==='1';
function httpConn(host,port,user,pass,th,tp,to=8000){return new Promise(res=>{
  let done=false,buf='',s=null;
  const fin=(sock,why)=>{if(done)return;done=true;clearTimeout(timer);if(!sock){try{s&&s.destroy()}catch(e){}}res({sock,why})};
  const timer=setTimeout(()=>fin(null,'timeout'),to);
  try{s=net.connect({host,port:+port,timeout:to})}catch(e){fin(null,'conn');return}
  s.on('timeout',()=>fin(null,'timeout'));
  s.on('error',e=>fin(null,e&&e.code==='ENOTFOUND'?'dns':(e&&e.code==='ECONNREFUSED'?'refused':'conn')));
  s.on('connect',()=>{let h='CONNECT '+th+':'+tp+' HTTP/1.1\r\nHost: '+th+':'+tp+'\r\n';
    if(user)h+='Proxy-Authorization: Basic '+Buffer.from(user+':'+(pass||'')).toString('base64')+'\r\n';
    try{s.write(h+'\r\n')}catch(e){fin(null,'conn')}});
  const onD=d=>{buf+=d.toString('latin1');if(buf.indexOf('\r\n\r\n')<0){if(buf.length>8000)fin(null,'proto');return}
    s.removeListener('data',onD);const m=/^HTTP\/1\.[01]\s+(\d{3})/.exec(buf);
    if(m&&+m[1]===200)fin(s,null);else fin(null,m?'denied':'proto')};
  s.on('data',onD)})}
async function e2eProbe(host,port,user,pass,proto,to=10000){
  const t0=Date.now(),T=E2E_HOST;
  const c=proto==='http'?await httpConn(host,port,user,pass,T,443,to):await socksConn(host,port,user,pass,T,443,to);
  if(!c.sock)return{ms:null,why:c.why||'conn'};
  const sock=c.sock;sock.removeAllListeners('data');sock.removeAllListeners('timeout');sock.removeAllListeners('error');sock.on('error',()=>{});sock.setTimeout(0);
  return await new Promise(res=>{
    let raw='',done=false,ts=null,phase=1,ip='',cc='',total=0,t2=0;
    const fin=o=>{if(done)return;done=true;clearTimeout(tm);try{ts&&ts.destroy()}catch(e){}try{sock.destroy()}catch(e){}res(o)};
    const tm=setTimeout(()=>fin(phase===2&&ip?{ms:total,total,ip,cc}:{ms:null,why:'tls-timeout'}),Math.max(3500,to-(Date.now()-t0)));
    const req=k=>'GET /cdn-cgi/trace HTTP/1.1\r\nHost: '+T+'\r\nConnection: '+k+'\r\nUser-Agent: BATAMN\r\n\r\n';
    try{ts=tls.connect({socket:sock,servername:T,rejectUnauthorized:!E2E_INSECURE,ALPNProtocols:['http/1.1']})}catch(e){fin({ms:null,why:'tls'});return}
    ts.on('error',()=>fin(phase===2&&ip?{ms:total,total,ip,cc}:{ms:null,why:'tls'}));
    ts.on('secureConnect',()=>{try{ts.write(req('keep-alive'))}catch(e){fin({ms:null,why:'conn'})}});
    ts.on('data',d=>{raw+=d.toString('utf8');
      if(phase===1){const he=raw.indexOf('\r\n\r\n');if(he<0)return;
        const cl=/content-length:\s*(\d+)/i.exec(raw.slice(0,he)),body=raw.slice(he+4);
        const full=cl?Buffer.byteLength(body)>=+cl[1]:/\r\n0\r\n\r\n$/.test(raw);
        if(!full)return;
        const mi=/^ip=(\S+)/m.exec(body),ml=/^loc=([A-Z]{2})/m.exec(body);
        if(!mi||!ml){fin({ms:null,why:'no-trace'});return}
        ip=mi[1];cc=ml[1];total=Date.now()-t0;phase=2;raw='';t2=Date.now();
        try{ts.write(req('close'))}catch(e){fin({ms:total,total,ip,cc})}
      }else if(/^HTTP\/1\.[01] \d{3}/.test(raw)){fin({ms:Date.now()-t2,total,ip,cc})}});
    ts.on('end',()=>fin(phase===2&&ip?{ms:total,total,ip,cc}:{ms:null,why:'no-trace'}))})}
const socksTest=(h,p,u,pw,to=8000)=>e2eProbe(h,p,u,pw,'socks5',to).then(r=>({ms:r.ms,why:r.why,ip:r.ip,cc:r.cc}));
const httpTest=(h,p,u,pw,to=8000)=>e2eProbe(h,p,u,pw,'http',to).then(r=>({ms:r.ms,why:r.why,ip:r.ip,cc:r.cc}));
async function detectProto(host,port,user,pass,to=9000){
  const out=await Promise.all([e2eProbe(host,port,user,pass,'socks5',to),e2eProbe(host,port,user,pass,'http',to)]);
  const ok=[out[0].ms!=null?{proto:'socks5',...out[0]}:null,out[1].ms!=null?{proto:'http',...out[1]}:null].filter(Boolean).sort((a,b)=>a.ms-b.ms);
  if(ok.length)return{proto:ok[0].proto,ms:ok[0].ms,ip:ok[0].ip,cc:ok[0].cc};
  return{proto:'',ms:null,why:out[0].why||out[1].why||'conn'}}
const ccName=cc=>{try{return new Intl.DisplayNames(['en'],{type:'region'}).of(cc)||''}catch(e){return''}};
async function geoIP(ip){
  ip=String(ip||'').trim();if(!ip)return null;
  const eps=[
    ['https://ipwho.is/'+ip,j=>(j&&j.success!==false&&j.country_code)?{cc:j.country_code,country:j.country||''}:null],
    ['https://ipinfo.io/'+ip+'/json',j=>j&&j.country?{cc:j.country,country:''}:null],
    ['http://ip-api.com/json/'+ip+'?fields=status,country,countryCode',j=>(j&&j.status==='success')?{cc:j.countryCode,country:j.country||''}:null]];
  for(const ep of eps){
    try{
      const r=await fetch(ep[0],{headers:{'User-Agent':'BATAMN'},signal:AbortSignal.timeout(8000)});
      if(!r.ok)continue;
      const g=ep[1](await r.json());
      if(g&&/^[A-Za-z]{2}$/.test(g.cc||''))return{cc:g.cc.toUpperCase(),country:cleanLoc(g.country)};
    }catch(e){}
  }
  return null}
const ccFlag=cc=>{cc=String(cc||'').toUpperCase();return /^[A-Z]{2}$/.test(cc)?'['+cc+']':''};
async function socksEgress(host,port,user,pass,proto){
  const r=await e2eProbe(host,port,user,pass,proto==='http'?'http':'socks5',10000);
  if(r.ms==null)return{why:r.why};
  return{ip:r.ip,cc:r.cc,country:cleanLoc(ccName(r.cc))}}
async function geoFill(g,host,port,user,pass,proto){
  if(!g||!g.ip)return g;
  if(!g.country){
    try{const gj=await geoIP(g.ip);if(gj){g.country=gj.country;g.cc=gj.cc}}catch(e){}
  }
  return g}
const tcpPing=(host,port,to=1800)=>new Promise(res=>{const t0=Date.now();let d=false;let s;
  const f=v=>{if(!d){d=true;try{s&&s.destroy()}catch(e){}res(v)}};
  try{s=net.connect({host,port:+port})}catch(e){return f(null)}
  s.setTimeout(to,()=>f(null));s.on('connect',()=>f(Date.now()-t0));s.on('error',()=>f(null))});
const shuffle=a=>{for(let i=a.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[a[i],a[j]]=[a[j],a[i]]}return a};
async function fetchProxies(urls){const out=new Map();
  for(const u of urls){try{const r=await fetch(u,{headers:{'User-Agent':'BATAMN'},signal:AbortSignal.timeout(25000)});if(!r.ok)continue;
    const t=await r.text();
    const re=/(?:([A-Za-z0-9._~%!$&'()*+,;=-]{1,64}):([^@\s:]{1,64})@)?(\d{1,3}(?:\.\d{1,3}){3}|[a-zA-Z0-9.-]{2,253}):(\d{2,5})/g;let m;
    while((m=re.exec(t))&&out.size<20000){const host=m[3],port=+m[4];if(!host||port<1||port>65535)continue;
      if(/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(host))continue;
      out.set(host+':'+port,{host,port,user:m[1]||'',pass:m[2]||''})}}catch(e){}}
  return[...out.values()]}


// ---------- diagnostics: Railway edge -> panel -> Xray ----------
function wsProbe(o,to=7000){return new Promise(res=>{
  const key=crypto.randomBytes(16).toString('base64'),t0=Date.now();let buf='',done=false,s=null;
  const fin=(ok,msg)=>{if(done)return;done=true;clearTimeout(tm);try{s&&s.destroy()}catch(e){}res({ok,msg,ms:Date.now()-t0})};
  const tm=setTimeout(()=>fin(false,'timeout'),to);
  const send=()=>{try{s.write('GET '+o.path+' HTTP/1.1\r\nHost: '+o.hostHeader+'\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: '+key+'\r\n\r\n')}catch(e){fin(false,'write')}};
  try{s=o.tls?tls.connect({host:o.host,port:o.port,servername:o.host,ALPNProtocols:['http/1.1']},send):net.connect({host:o.host,port:o.port},send)}catch(e){fin(false,'conn');return}
  s.on('error',e=>fin(false,e.code||e.message));
  s.on('data',d=>{buf+=d.toString('latin1');const m=/^HTTP\/1\.[01] (\d{3})/.exec(buf);if(m)fin(m[1]==='101',m[1]==='101'?'101 Switching Protocols':'HTTP '+m[1])})})}
async function runDiag(host){
  const out=[],add=(k,ok,msg,hint)=>out.push({k,ok,msg:String(msg||'').slice(0,160),hint:hint||''});
  const up=!!(xray&&xray.exitCode===null);
  add('Xray',up&&!xrayErr,xrayErr||(up?'running':'not running'),(up&&!xrayErr)?'':'متن لاگ پایین رو برام بفرست');
  try{const t0=Date.now(),r=await fetch('https://www.gstatic.com/generate_204',{signal:AbortSignal.timeout(8000)});add('Internet',r.status===204,'HTTP '+r.status+' · '+(Date.now()-t0)+'ms','')}
  catch(e){add('Internet',false,e.message,'سرور به اینترنت وصل نیست (محدودیت پلن/شبکه)')}
  const ibs=db.inbounds.filter(i=>i.on);
  for(const i of ibs.slice(0,6)){const l=await wsProbe({host:'127.0.0.1',port:i.port,path:i.path,hostHeader:host});
    add('Local · '+i.name,l.ok,l.msg,l.ok?'':'Xray روی این اینباند جواب نمی‌ده')}
  if(ibs[0]){const p=await wsProbe({tls:true,host,port:443,path:ibs[0].path,hostHeader:host});
    add('Public · '+host,p.ok,p.msg+' · '+p.ms+'ms',p.ok?'':'مسیر دامنه ← پنل ← Xray کار نمی‌کنه: پورت دامنه رو چک کن (باید با PORT یکی باشه)، یا پلتفرم WebSocket/پراکسی رو محدود کرده')}
  const locs=db.locs||[];if(locs.length){const n=locs.filter(l=>l.on).length;add('Locations',n>0,n+' فعال از '+locs.length,'پروکسی‌های رایگان زود می‌میرن؛ لوکیشن مرده = خروج مستقیم از سرور')}
  return{checks:out,log:xrayLog.slice(-12),host}}

// ---------- loc health monitor (auto-disable dead proxies) ----------
let lastLocCheck = 0;
const locFails = new Map();
setInterval(async () => {
  if (db.settings.locHealth === false) return;
  const everyMin = Math.max(5, Math.min(720, +db.settings.locHealthMin || 30));
  if (Date.now() - lastLocCheck < everyMin * 60000) return;
  lastLocCheck = Date.now();
  const list = (db.locs || []).filter(l => l.on).slice(0, 40);
  if (!list.length) return;
  const q = list.slice();
  await Promise.all(Array.from({ length: 5 }, async () => {
    while (q.length) {
      const l = q.shift();
      try {
        const r = await detectProto(l.host, l.port, l.user, l.pass, 5000);
        if (r.proto) { locFails.delete(l.id); l.ms = r.ms; l.why = null; l.proto = r.proto; }
        else {
          const n = (locFails.get(l.id) || 0) + 1; locFails.set(l.id, n);
          l.ms = null; l.why = r.why || 'conn';
          if (n >= 2) { l.on = false; console.log('[loc-health] auto-disabled', l.host + ':' + l.port, l.why); }
        }
      } catch (e) {}
    }
  }));
  try { save() } catch (e) {}
  if ([...locFails.values()].some(n => n >= 2)) { locFails.clear(); restartSoon(); }
}, 60000);

// ---------- auth ----------
const sign=e=>crypto.createHmac('sha256',db.secret).update(String(e)).digest('hex');
const mkToken=()=>{const e=Date.now()+30*864e5;return e+'.'+sign(e)};
const authed=req=>{const c=(req.headers.cookie||'').split(/;\s*/).find(x=>x.startsWith('bt='));if(!c)return false;
  const[e,s]=c.slice(3).split('.');return !!s&&+e>Date.now()&&crypto.timingSafeEqual(Buffer.from(sign(e)),Buffer.from(s.padEnd(64,'x').slice(0,64)))};
const fails={};
const secLog=[];const secPush=(ip,ok)=>{secLog.unshift({ip,t:Date.now(),ok:!!ok});if(secLog.length>60)secLog.length=60};
const clientIp=req=>{const x=String(req.headers['x-forwarded-for']||'').split(',').map(v=>v.trim()).filter(Boolean);return String(x[x.length-1]||req.headers['x-real-ip']||req.socket.remoteAddress||'').replace(/^::ffff:/,'')};
// speed-test helpers (only for known active users or the logged-in admin)
const SPBUF=crypto.randomBytes(65536),spQ={};
const spOk=(ip,add)=>{const n=Date.now(),q=spQ[ip]||(spQ[ip]={b:0,t:n});if(n-q.t>60000){q.b=0;q.t=n}if(q.b+add>300e6)return false;q.b+=add;return true};
const hostOf=req=>{const h=String(req.headers['x-forwarded-host']||req.headers.host||'').split(',')[0].trim().split(':')[0].toLowerCase();return h||'localhost'};
const cleanHost=s=>{s=String(s||'').trim().toLowerCase().replace(/^https?:\/\//,'').split('/')[0].split(':')[0];return /^[a-z0-9.-]{3,253}$/.test(s)&&s.includes('.')?s:''};
const effHost=(req,h)=>cleanHost(db.settings.host)||process.env.PUBLIC_HOST||process.env.RAILWAY_PUBLIC_DOMAIN||h||hostOf(req);
const isSecure=req=>{const p=String(req.headers['x-forwarded-proto']||'').toLowerCase();if(p)return p.split(',')[0].trim()!=='http';return !!req.socket.encrypted};
const sessCookie=(req,tok)=>'bt='+tok+'; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax'+(isSecure(req)?'; Secure':'');
const zlib=require('zlib');
const J=(res,o,c=200)=>{const t=JSON.stringify(o),ae=String((res.req&&res.req.headers['accept-encoding'])||'');
  if(t.length>4096&&/\bgzip\b/.test(ae)){zlib.gzip(t,(e,z)=>{if(res.writableEnded||res.destroyed)return;if(e){res.writeHead(c,{'content-type':'application/json'});return res.end(t)}res.writeHead(c,{'content-type':'application/json','content-encoding':'gzip',vary:'accept-encoding'});res.end(z)})}
  else{res.writeHead(c,{'content-type':'application/json'});res.end(t)}};
const body=req=>new Promise(r=>{const lim=req.url.startsWith('/api/restore')?2e7:req.url.startsWith('/node/report')?5e6:1e5;let b='',big=false,done=false;
  const fin=v=>{if(!done){done=true;r(v)}};
  req.on('data',c=>{if(big)return;b+=c;if(b.length>lim){big=true;b=''}});
  req.on('end',()=>{if(big)return fin({__tooBig:1});try{const j=JSON.parse(b||'{}');fin(j&&typeof j==='object'&&!Array.isArray(j)?j:{})}catch(e){fin({})}});
  req.on('error',()=>fin({}));req.on('close',()=>fin({}))});
const cleanTg=x=>{x=String(x||'').trim().replace(/^https?:\/\/t\.me\//,'').replace(/^@/,'');return /^[A-Za-z0-9_]{3,40}$/.test(x)?x:''};
const contact=()=>({support:db.settings.support!=null?db.settings.support:'mamadi1048',channel:db.settings.channel!=null?db.settings.channel:'editmamad_e'});
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const cleanName=s=>String(s||'user').slice(0,30).replace(/[^\w\u0600-\u06FF -]/g,'').trim()||'user';
const pubUser=(u,h,addr,withLinks)=>({days:dates14().map(d=>(u.days||{})[d]||0),maxDev:u.maxDev||0,online:onlineOf(u.id).length,id:u.id,name:u.name,on:u.on,created:u.created,limit:u.limit,exp:u.exp,used:u.used,note:u.note,status:status(u),...(withLinks?{links:linksFor(u,h,addr)}:{})});


// ---------- worker nodes ----------
const sha256=x=>crypto.createHash('sha256').update(String(x)).digest('hex');
const nodeAuth=req=>{const t=String(req.headers.authorization||'').replace(/^Bearer\s+/i,'');if(!t||!db.nodes)return null;const h=sha256(t);return db.nodes.find(n=>eqs(n.tokenHash,h))||null};
const nodePub=n=>({id:n.id,name:n.name,domain:n.domain||'',cc:n.cc||'',ccManual:!!n.ccManual,label:n.label||'',on:!!n.on,all:!!n.all,created:n.created,lastSeen:n.lastSeen||0,connected:Date.now()-(n.lastSeen||0)<60000,up:n.up==null?null:!!n.up,ms:n.ms==null?null:n.ms,checked:n.checked||0});
const cleanDomain=v=>{v=String(v==null?'':v).trim().toLowerCase().replace(/^https?:\/\//,'').replace(/[\/?#].*$/,'').replace(/:\d+$/,'');return /^[a-z0-9]([a-z0-9.-]{1,251})[a-z0-9]$/.test(v)||v===''?v:null};
async function probeNodes(){for(const n of db.nodes||[]){if(!n.domain)continue;const t0=Date.now();
  try{const r=await fetch('https://'+n.domain+'/health',{signal:AbortSignal.timeout(8000),redirect:'manual'});n.up=r.ok&&(await r.text()).trim()==='ok';n.ms=n.up?Date.now()-t0:null}catch(e){n.up=false;n.ms=null}n.checked=Date.now()}}
if(!NODE_MODE){setInterval(probeNodes,60000);setTimeout(probeNodes,8000)}
if(NODE_MODE){
  const MASTER=String(process.env.MASTER_URL).replace(/\/+$/,''),NT=process.env.NODE_TOKEN;
  const call=(p,opt)=>fetch(MASTER+p,{...opt,headers:{authorization:'Bearer '+NT,'content-type':'application/json'},signal:AbortSignal.timeout(15000)});
  async function nodeSync(){try{const r=await call('/node/sync');if(!r.ok){if(r.status===401){db.users=[];if(sig()!==lastSig)startXray()}throw new Error('master said HTTP '+r.status)}const j=await r.json();
    db.users=(j.users||[]).map(x=>({id:String(x.id),name:String(x.name||'').slice(0,30),on:true,limit:0,exp:0,used:0,maxDev:0,created:0}));
    db.inbounds=(j.inbounds||[]).map(i=>({id:i.id,name:i.name,proto:i.proto,net:i.net,path:i.path,port:+i.port,on:true}));
    blocks.clear();(j.blocks||[]).forEach(b=>blocks.set(b.uid+'|'+b.rule,{uid:b.uid,rule:b.rule,exp:Date.now()+300000}));
    nodeErr='';if(sig()!==lastSig)startXray()}catch(e){nodeErr=e.message;console.log('[node] sync failed:',e.message)}}
  async function nodeReport(){const used=NODE_PEND;NODE_PEND={};const ips={};
    for(const uid of online.keys()){const o=onlineOf(uid);if(o.length)ips[uid]=o.map(e=>e.ip)}
    try{const r=await call('/node/report',{method:'POST',body:JSON.stringify({used,ips,cc:SRV_CC})});if(!r.ok)throw new Error('HTTP '+r.status)}
    catch(e){for(const k in used)NODE_PEND[k]=(NODE_PEND[k]||0)+used[k];console.log('[node] report failed:',e.message)}}
  setTimeout(nodeSync,500);setInterval(nodeSync,15000);setInterval(nodeReport,10000);
  console.log('[node] running as worker for',MASTER);
}

// ---------- SSH over WebSocket (payload mode): per-user accounts, byte accounting, device limit, private-network block ----------
let ssh2=null;try{ssh2=require('ssh2')}catch(e){console.log('[ssh] ssh2 module not installed: SSH disabled')}
const dnsP=require('dns').promises;
const PRIV=new net.BlockList();
[['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.168.0.0',16],['224.0.0.0',4],['240.0.0.0',4]].forEach(([a,p])=>PRIV.addSubnet(a,p,'ipv4'));
[['::1',128],['fc00::',7],['fe80::',10],['ff00::',8]].forEach(([a,p])=>PRIV.addSubnet(a,p,'ipv6'));
const isPriv=a=>{try{return PRIV.check(a,net.isIPv6(a)?'ipv6':'ipv4')}catch(e){return true}};
const sshOn=()=>!!(ssh2&&db.settings.sshOn);
function ensureSsh(){let ch=false;const used=new Set(db.users.filter(u=>u.ssh&&u.ssh.user).map(u=>u.ssh.user));
  for(const u of db.users){if(u.ssh&&u.ssh.user&&u.ssh.pass)continue;let nm;do nm='u'+crypto.randomBytes(3).toString('hex');while(used.has(nm));used.add(nm);u.ssh={user:nm,pass:crypto.randomBytes(7).toString('base64url')};ch=true}
  if(ch)save()}
const eqs=(a,b)=>{const x=Buffer.from(String(a)),y=Buffer.from(String(b));return x.length===y.length&&crypto.timingSafeEqual(x,y)};
function sshHostKey(){const f=path.join(DIR,'ssh_host_rsa.pem');try{return fs.readFileSync(f,'utf8')}catch(e){}
  const k=crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs1',format:'pem'}}).privateKey;
  try{fs.writeFileSync(f,k,{mode:0o600})}catch(e){}return k}
const sshPend=new Map(),sshF={};
const sshAcc=(u,n)=>sshPend.set(u.id,(sshPend.get(u.id)||0)+n);
setInterval(()=>{let ch=false;for(const[id,n]of sshPend){const u=db.users.find(x=>x.id===id);if(u){u.used+=n;addTraffic(u,n);ch=true}}sshPend.clear();if(ch)save()},3000);
function devOk(u,ip){if(!u.maxDev)return true;const k=ipKey(ip).key,on=onlineOf(u.id).sort((a,b)=>a.first-b.first);return on.length<u.maxDev||on.slice(0,u.maxDev).some(e=>e.ip===k)}
const sshBlocked=ip=>{const f=sshF[ip];return !!f&&Date.now()-f.t<600000&&f.n>=10};
function sshFail(ip){const f=sshF[ip]&&Date.now()-sshF[ip].t<600000?sshF[ip]:(sshF[ip]={n:0,t:Date.now()});f.n++}
async function sshTunnel(u,ip,accept,reject,i){
  try{
    const port=+i.destPort;if(!isActive(u)||!(port>0&&port<65536)||port===25)return reject();
    let addr=String(i.destIP||'');if(!net.isIP(addr))addr=(await dnsP.lookup(addr,{family:4})).address;
    if(isPriv(addr))return reject();
    const s=net.connect({host:addr,port});let done=false;s.setNoDelay(true);s.setTimeout(15000,()=>{if(!done)s.destroy()});
    s.once('error',()=>{if(!done){done=true;try{reject()}catch(e){}}});
    s.once('connect',()=>{if(done)return;done=true;s.setTimeout(0);
      const ch=accept();if(!ch){s.destroy();return}
      const end=()=>{try{ch.close()}catch(e){}s.destroy()};
      const cnt=n=>{sshAcc(u,n);if(!isActive(u))end()};
      ch.on('data',d=>cnt(d.length));s.on('data',d=>cnt(d.length));
      ch.pipe(s);s.pipe(ch);ch.on('close',end);ch.on('error',end);s.on('close',end);s.on('error',end)})
  }catch(e){try{reject()}catch(_){}}}
let sshSrv=null;
function sshInit(){if(!ssh2||sshSrv)return;try{
  sshSrv=new ssh2.Server({hostKeys:[sshHostKey()],banner:'BATAMN'},(client,info)=>{
    const ip=String(info&&info.ip||'');let u=null,tm=null;
    client.on('error',()=>{});client.on('close',()=>clearInterval(tm));
    client.on('authentication',ctx=>{
      if(ctx.method!=='password')return ctx.reject(['password']);
      if(sshBlocked(ip)){try{client.end()}catch(e){}return ctx.reject([])}
      const x=sshOn()?db.users.find(v=>v.ssh&&eqs(v.ssh.user,ctx.username)):null;
      if(!x||!eqs(x.ssh.pass,ctx.password)||!isActive(x)||!devOk(x,ip)){sshFail(ip);return ctx.reject(['password'])}
      u=x;ctx.accept()});
    client.on('ready',()=>{seen(u.id,ip);tm=setInterval(()=>seen(u.id,ip),30000);
      client.on('session',(accept,reject)=>reject());
      client.on('tcpip',(accept,reject,i)=>sshTunnel(u,ip,accept,reject,i))});
  })}catch(e){console.log('[ssh] init failed:',e.message);sshSrv=null}}
const sshWant=req=>!!(sshSrv&&sshOn()&&/^\/(?:ssh)?(?:\?.*)?$/.test(req.url));
function sshAttach(req,sock,head){
  const key=req.headers['sec-websocket-key'];
  let r='HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n';
  if(key)r+='Sec-WebSocket-Accept: '+crypto.createHash('sha1').update(key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')+'\r\n';
  sock.on('error',()=>{});sock.setNoDelay(true);sock.setKeepAlive(true,30000);sock.setTimeout(0);
  try{Object.defineProperty(sock,'remoteAddress',{value:clientIp(req),configurable:true});Object.defineProperty(sock,'remotePort',{value:0,configurable:true})}catch(e){}
  sock.write(r+'\r\n');if(head&&head.length)sock.unshift(head);
  try{sshSrv.injectSocket(sock)}catch(e){sock.destroy()}}
if(db.settings.sshOn){ensureSsh();sshInit()}

const SERVER=http.createServer((req,res)=>{HANDLE(req,res).catch(e=>{console.log('[http] handler error:',e&&e.stack||e);try{if(!res.headersSent)res.writeHead(500,{'content-type':'application/json'});res.end('{"e":"server error"}')}catch(_){}})});
async function HANDLE(req,res){
  let U0;try{U0=new URL(req.url,'http://x')}catch(e){res.writeHead(400);return res.end('Bad request')}
  const U=U0,u=U.pathname,h=hostOf(req),addr=cleanAddr(U.searchParams.get('addr'));
  if(NODE_MODE){if(u==='/health')return res.end('ok');res.writeHead(404);return res.end('Not found')}
  if(u==='/node/sync'&&req.method==='GET'){const n=nodeAuth(req);if(!n)return J(res,{e:1},401);n.lastSeen=Date.now();
    return J(res,{users:db.users.filter(isActive).map(x=>({id:x.id,name:x.name})),inbounds:db.inbounds.filter(i=>i.on&&!i.egress).map(i=>({id:i.id,name:i.name,proto:i.proto,net:i.net,path:i.path,port:i.port})),blocks:[...blocks.values()].map(b=>({uid:b.uid,rule:b.rule}))})}
  if(u==='/node/report'&&req.method==='POST'){const n=nodeAuth(req);if(!n)return J(res,{e:1},401);const b=await body(req);
    if(b.used&&typeof b.used==='object')for(const id of Object.keys(b.used).slice(0,5000)){const x=db.users.find(v=>v.id===id),d=+b.used[id];if(x&&d>0&&d<1e12){x.used+=d;addTraffic(x,d)}}
    if(b.ips&&typeof b.ips==='object')for(const id of Object.keys(b.ips).slice(0,5000)){if(!db.users.some(v=>v.id===id))continue;(Array.isArray(b.ips[id])?b.ips[id]:[]).slice(0,20).forEach(ip=>{if(typeof ip==='string'&&ip.length<64)seen(id,ip)})}
    n.lastSeen=Date.now();if(/^[A-Z]{2}$/.test(String(b.cc||''))&&!n.ccManual)n.cc=b.cc;save();return J(res,{ok:1})}
  if(FILES[u]&&req.method==='GET'){const bufr=u==='/'?Buffer.from(FILES[u].toString().replace('__THEME__','gotham')):FILES[u];return res.writeHead(200,{'content-type':STATIC[u][1],'cache-control':u==='/bg.svg'?'public,max-age=86400':'no-cache'}),res.end(bufr)}
  if(u.startsWith('/fonts/')){const f=fontFile(u.slice(7));if(!f){res.writeHead(404);return res.end()}res.writeHead(200,{'content-type':'font/woff2','cache-control':'public,max-age=31536000,immutable'});return fs.createReadStream(f).pipe(res)}
  if(u==='/health')return res.end('ok');
  if(u==='/qr'){if(!rate(clientIp(req),'qr',40)){res.writeHead(429);return res.end()}const s=qrSvg((U.searchParams.get('d')||'').slice(0,1500));return res.writeHead(s?200:404,{'content-type':'image/svg+xml'}),res.end(s)}
  if(u.startsWith('/speed/')){
    const uid=U.searchParams.get('u'),okU=authed(req)||db.users.some(x=>x.id===uid&&isActive(x));
    if(!okU){res.writeHead(403);return res.end()}
    const ip=clientIp(req);
    if(u==='/speed/ping'){res.writeHead(204,{'cache-control':'no-store'});return res.end()}
    if(u==='/speed/down'){const n=Math.min(60e6,Math.max(1e5,+U.searchParams.get('bytes')||2e7));if(!spOk(ip,n)){res.writeHead(429);return res.end()}
      res.writeHead(200,{'content-type':'application/octet-stream','cache-control':'no-store','content-length':n});let sent=0;
      const pump=()=>{while(sent<n){const c=Math.min(65536,n-sent);sent+=c;if(!res.write(c===65536?SPBUF:SPBUF.subarray(0,c)))return res.once('drain',pump)}res.end()};
      req.on('close',()=>{sent=n});pump();return}
    if(u==='/speed/up'&&req.method==='POST'){if(!spOk(ip,12e6)){res.writeHead(429);return res.end()}let n=0;
      req.on('data',c=>{n+=c.length;if(n>24e6)req.destroy()});req.on('end',()=>J(res,{ok:1,bytes:n}));req.on('error',()=>{});return}
    res.writeHead(404);return res.end()}
  const lv=/^\/sub\/([^/]+)\/live$/.exec(u);
  if(lv){const x=db.users.find(v=>v.id===lv[1]);if(!x)return J(res,{e:1},404);return J(res,{online:onlineOf(x.id).length,max:x.maxDev||0,status:status(x)})}
  const mf=/^\/sub\/([^/]+)\/manifest$/.exec(u);
  if(mf){const x=db.users.find(v=>v.id===mf[1]);if(!x)return J(res,{e:1},404);
    return J(res,{name:'BATAMN · '+x.name,short_name:'BATAMN',start_url:'/sub/'+x.id,scope:'/sub/'+x.id,display:'standalone',dir:'rtl',lang:'fa',background_color:'#04060a',theme_color:'#04060a',icons:[{src:'/bg.svg',sizes:'any',type:'image/svg+xml',purpose:'any'}]})}
  if(u.startsWith('/sub/')){if(!rate(clientIp(req),'sub',90)){res.writeHead(429,{'content-type':'text/plain'});return res.end('Too many requests')}
    const x=db.users.find(v=>v.id===u.slice(5)),html=(req.headers.accept||'').includes('text/html')&&!U.searchParams.has('raw');
    if(!x){res.writeHead(404,{'content-type':'text/plain'});return res.end('Not found')}
    const hh=effHost(req,h),st=status(x),L=st==='active'?linksFor(x,hh,addr):[];
    if(!html){
      if(st!=='active'&&!subInfoOn()){res.writeHead(403,{'content-type':'text/plain'});return res.end(st)}
      res.writeHead(200,{'content-type':'text/plain; charset=utf-8','profile-title':'BATAMN','profile-update-interval':'1',...(contact().support?{'support-url':'https://t.me/'+contact().support}:{}),...(contact().channel?{'profile-web-page-url':'https://t.me/'+contact().channel}:{}),
        'subscription-userinfo':'upload=0; download='+x.used+'; total='+x.limit+'; expire='+(x.exp?Math.floor(x.exp/1000):0)});
      return res.end(Buffer.from((subInfoOn()?infoLinks(x,st):[]).concat(L.map(i=>i.l)).join('\n')).toString('base64'));
    }
    const subUrl='https://'+hh+'/sub/'+x.id+(addr?'?addr='+encodeURIComponent(addr):'');
    const fb=cleanHost(db.settings.fallback)||'';
    const data={ssh:(sshOn()&&(ensureSsh(),x.ssh)&&st==='active')?{user:x.ssh.user,pass:x.ssh.pass,host:addr||db.settings.addr||hh,sni:hh,port:443}:null,id:x.id,online:onlineOf(x.id).length,maxDev:x.maxDev||0,contact:contact(),sub:subUrl,host:hh,fallback:fb,altSub:fb?'https://'+fb+'/sub/'+x.id+(addr?'?addr='+encodeURIComponent(addr):''):null,pay:{card:String(db.settings.payCard||'').slice(0,32),url:String(db.settings.payUrl||'').slice(0,200)},bot:cleanTg(db.settings.botUser||''),status:st,used:x.used,limit:x.limit,exp:x.exp,created:x.created,days:dates14().map(d=>((x.days||{})[d]||0)),links:L.map(i=>({n:i.n,loc:i.loc||'',eg:i.eg||'',l:i.l,qr:qrSvg(i.l)}))};
    const page=SUB.replace('__THEME__','gotham').replace(/__NAME__/g,()=>esc(x.name)).replace('__QR__',()=>st==='active'?qrSvg(subUrl):'').replace('__DATA__',()=>JSON.stringify(data).replace(/</g,'\\u003c'));
    return res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store'}),res.end(page);
  }
  if(u==='/api/login'&&req.method==='POST'){
    const ip=clientIp(req),f=fails[ip]||{n:0,t:Date.now()};
    if(Date.now()-f.t>600000){f.n=0;f.t=Date.now()}
    if(f.n>=8)return J(res,{e:'تلاش زیاد. بعداً امتحان کن'},429);
    const b=await body(req);
    if(typeof b.pass==='string'&&b.pass===db.settings.pass){delete fails[ip];secPush(ip,1);res.setHeader('Set-Cookie',sessCookie(req,mkToken()));return J(res,{ok:1})}
    f.n++;fails[ip]=f;secPush(ip,0);return J(res,{e:'رمز اشتباهه'},401);
  }
  if(u==='/api/logout'){res.setHeader('Set-Cookie','bt=; Path=/; Max-Age=0; SameSite=Lax'+(isSecure(req)?'; Secure':''));return J(res,{ok:1})}
  if(u.startsWith('/api/')){
    if(!authed(req))return J(res,{e:1},401);
    if(u==='/api/me')return J(res,{ok:1});
    if(u==='/api/xray/restart'){startXray(true);return J(res,{ok:1})}
    if(u==='/api/sys')return J(res,{cpu:cpuPct,cores:+cpuCores.toFixed(1),mem:memInfo(),disk:diskInfo(),net:{rx:NS.rx,tx:NS.tx,rxs:NS.rxs,txs:NS.txs},
      pup:process.uptime(),load:os.loadavg(),conns,online:onlineSummary(),region:process.env.RAILWAY_REPLICA_REGION||process.env.RAILWAY_REGION||'—',
      xray:{on:!!(xray&&xray.exitCode===null),mem:xrayMem(),err:xrayErr}});
    if(u==='/api/state'){if(sshOn())ensureSsh();
      const D=dates14(),hh=effHost(req,h);return J(res,{host:hh,realHost:h,settings:{linkExtra:linkExtra(),subInfo:subInfoOn(),locName:db.settings.locName||'',nameStyle:NAME_STYLES.includes(db.settings.nameStyle)?db.settings.nameStyle:'bold',autoLoc:styleText(autoLoc()),sshOn:!!db.settings.sshOn,sshReady:!!ssh2,addr:db.settings.addr,host:db.settings.host||'',fallback:db.settings.fallback||'',theme:'gotham',plans:Array.isArray(db.settings.plans)?db.settings.plans:[],payCard:db.settings.payCard||'',payUrl:db.settings.payUrl||'',botUser:db.settings.botUser||'',hasBotToken:!!db.settings.botToken,scanAuto:!!db.settings.scanAuto,scanEveryH:Math.max(1,Math.min(72,+db.settings.scanEveryH||12)),sources:srcList(),...contact(),...repoCfg(),auto:!!db.settings.auto,hasToken:!!db.settings.token},version:curVersion(),inbounds:db.inbounds,nodes:(db.nodes||[]).map(nodePub),daily:{dates:D,total:D.map(d=>(db.daily||{})[d]||0)},
        users:db.users.map(x=>({...pubUser(x,hh,addr,true),...(sshOn()&&x.ssh?{ssh:x.ssh}:{})})),totalUsed:db.users.reduce((a,x)=>a+x.used,0)});
    }
    if(u==='/api/backup')return J(res,{ok:1,at:Date.now(),db});
    if(u==='/api/security')return J(res,{log:secLog,banned:Object.keys(fails).filter(k=>(fails[k].n>=8))});
    if(u==='/api/bot/test'){try{const r=await fetch('https://api.telegram.org/bot'+db.settings.botToken+'/getMe',{signal:AbortSignal.timeout(15000)});const j=await r.json();if(!j.ok)throw new Error('توکن نامعتبره');return J(res,{ok:1,bot:j.result})}catch(e){return J(res,{e:'اتصال به تلگرام ناموفق بود'},502)}}
    const b=await body(req);
    if(b.__tooBig)return J(res,{e:'حجم درخواست زیاده'},413);
    if(u==='/api/restore'){const d=b.db||b;if(!d||!Array.isArray(d.users)||!Array.isArray(d.inbounds))return J(res,{e:'فایل بکاپ معتبر نیست'},400);
      const num=(v,mx)=>{v=+v;return isFinite(v)&&v>0?Math.min(v,mx||1e15):0};
      const users=[],seenId=new Set();
      for(const x of d.users){if(!x||typeof x.id!=='string'||!x.id||x.id.length>64||seenId.has(x.id))continue;seenId.add(x.id);
        const days={};if(x.days&&typeof x.days==='object')for(const k of Object.keys(x.days).slice(0,60))if(/^\d{4}-\d\d-\d\d$/.test(k))days[k]=num(x.days[k]);
        users.push({id:x.id,name:cleanName(x.name),on:x.on!==false,created:num(x.created)||Date.now(),limit:num(x.limit),exp:num(x.exp),used:num(x.used),maxDev:Math.floor(num(x.maxDev,1000)),note:String(x.note||'').slice(0,100),days,
          ...(x.ssh&&typeof x.ssh.user==='string'&&typeof x.ssh.pass==='string'?{ssh:{user:x.ssh.user.slice(0,40),pass:x.ssh.pass.slice(0,64)}}:{})})}
      const inbs=[],paths=new Set(),ports=new Set();
      for(const i of d.inbounds){if(!i||typeof i.id!=='string'||!/^\/[A-Za-z0-9_-]{1,30}$/.test(String(i.path))||paths.has(i.path))continue;
        if(!['vless','vmess','trojan'].includes(i.proto)||!['ws','httpupgrade'].includes(i.net))continue;
        let port=Math.floor(+i.port);if(!(port>=10000&&port<65000)||port===10085||ports.has(port))port=Math.max(10000,...ports,...inbs.map(z=>z.port))+1;
        paths.add(i.path);ports.add(port);inbs.push({id:i.id.slice(0,32),name:String(i.name||i.proto).slice(0,30),proto:i.proto,net:i.net,path:i.path,port,on:i.on!==false,loc:keepName(i.loc),...(i.egress?{egress:String(i.egress).slice(0,32)}:{})})}
      if(!users.length&&d.users.length)return J(res,{e:'هیچ کاربر معتبری توی فایل نبود'},400);
      if(!inbs.length)return J(res,{e:'هیچ اینباند معتبری توی فایل نبود'},400);
      db.users=users.slice(0,5000);db.inbounds=inbs.slice(0,50);
      if(Array.isArray(d.locs))db.locs=d.locs.filter(l=>l&&typeof l.id==='string'&&typeof l.host==='string'&&+l.port>0).slice(0,100);
      if(Array.isArray(d.nodes))db.nodes=d.nodes.filter(n=>n&&typeof n.id==='string'&&typeof n.tokenHash==='string').slice(0,30);
      if(d.daily&&typeof d.daily==='object'){db.daily={};for(const k of Object.keys(d.daily).slice(0,60))if(/^\d{4}-\d\d-\d\d$/.test(k))db.daily[k]=num(d.daily[k])}
      if(d.settings&&typeof d.settings==='object'){const keep=db.settings.pass;Object.assign(db.settings,d.settings);if(typeof db.settings.pass!=='string'||db.settings.pass.length<6)db.settings.pass=keep}
      save();restartSoon();return J(res,{ok:1,n:db.users.length,inbounds:db.inbounds.length,nodes:(db.nodes||[]).length,locs:(db.locs||[]).length})}
    if(u==='/api/users/bulk'){const ids=new Set(Array.isArray(b.ids)?b.ids:[]);if(!ids.size)return J(res,{e:'کاربری انتخاب نشده'},400);
      if(b.action==='delete'){db.users=db.users.filter(x=>!ids.has(x.id))}
      else if(b.action==='reset'){db.users.forEach(x=>{if(ids.has(x.id))x.used=0})}
      else if(b.action==='extend'){const d=Math.max(1,Math.min(3650,Math.floor(+b.days||0)));if(!d)return J(res,{e:'روز نامعتبره'},400);const now=Date.now();db.users.forEach(x=>{if(ids.has(x.id))x.exp=Math.max(now,x.exp||0)+d*864e5})}
      else return J(res,{e:'نامعتبر'},400);
      save();restartSoon();return J(res,{ok:1})}
    if(u==='/api/user/kick'){const x=db.users.find(v=>v.id===b.id);if(!x)return J(res,{e:1},404);
      const rule=String(b.rule||'').slice(0,64);if(!rule)return J(res,{e:'IP نامعتبره'},400);
      blocks.set(x.id+'|'+rule,{uid:x.id,rule,exp:Date.now()+30*60000});restartSoon();return J(res,{ok:1})}
    if(u==='/api/users'){db.users.push({id:crypto.randomUUID(),name:cleanName(b.name),on:true,created:Date.now(),
        limit:Math.max(0,+b.gb||0)*GB,exp:b.days>0?Date.now()+b.days*864e5:0,used:0,maxDev:Math.max(0,Math.floor(+b.maxDev||0)),note:String(b.note||'').slice(0,100)});save();restartSoon();return J(res,{ok:1})}
    if(u==='/api/user/update'){const x=db.users.find(v=>v.id===b.id);if(!x)return J(res,{e:1},404);
      if(b.name!=null)x.name=cleanName(b.name);if(b.gb!=null)x.limit=Math.max(0,+b.gb||0)*GB;if(b.exp!=null)x.exp=Math.max(0,+b.exp||0);
      if(b.note!=null)x.note=String(b.note).slice(0,100);if(b.maxDev!=null)x.maxDev=Math.max(0,Math.floor(+b.maxDev||0));if(b.on!=null)x.on=!!b.on;if(b.reset)x.used=0;save();restartSoon();return J(res,{ok:1})}
    if(u==='/api/user/del'){db.users=db.users.filter(v=>v.id!==b.id);save();restartSoon();return J(res,{ok:1})}
    if(u==='/api/inbounds'){
      const pth=String(b.path||'').trim();
      if(!/^\/[A-Za-z0-9_-]{1,30}$/.test(pth))return J(res,{e:'مسیر نامعتبر (مثلاً /abc)'},400);
      if(db.inbounds.some(i=>i.path===pth))return J(res,{e:'این مسیر قبلاً استفاده شده'},400);
      if(!['vless','vmess','trojan'].includes(b.proto)||!['ws','httpupgrade'].includes(b.net))return J(res,{e:'نامعتبر'},400);
      const port=Math.max(10000,...db.inbounds.map(i=>i.port))+1;
      db.inbounds.push({id:'i'+Date.now().toString(36),port,on:true,proto:b.proto,net:b.net,path:pth,name:String(b.name||(b.proto.toUpperCase()+' · '+b.net.toUpperCase())).slice(0,30),loc:keepName(b.loc)});
      save();restartSoon();return J(res,{ok:1})}
    if(u==='/api/inbound/update'){const i=db.inbounds.find(v=>v.id===b.id);if(!i)return J(res,{e:1},404);
      if(b.on!=null)i.on=!!b.on;if(b.name)i.name=String(b.name).slice(0,30);if(b.loc!=null)i.loc=keepName(b.loc);
      if(b.egress!=null)i.egress=(db.locs||[]).some(l=>l.id===b.egress)?b.egress:'';save();restartSoon();return J(res,{ok:1})}
    if(u==='/api/inbound/del'){if(db.inbounds.length<=1)return J(res,{e:'حداقل یک اینباند لازمه'},400);db.inbounds=db.inbounds.filter(v=>v.id!==b.id);save();restartSoon();return J(res,{ok:1})}
    if(u==='/api/settings'){
      db.settings.theme='gotham';
      if(b.repo!=null){const v=String(b.repo).trim().replace(/^https?:\/\/github\.com\//,'').replace(/\.git$/,'').replace(/\/$/,'');if(v&&!/^[\w.-]+\/[\w.-]+$/.test(v))return J(res,{e:'ریپو باید به شکل owner/repo باشه'},400);db.settings.repo=v}
      if(b.branch!=null){const v=String(b.branch).trim();if(v&&!/^[\w./-]{1,60}$/.test(v))return J(res,{e:'برنچ نامعتبره'},400);db.settings.branch=v}
      if(b.token)db.settings.token=String(b.token).trim().slice(0,200);if(b.clearToken)delete db.settings.token;
      if(b.auto!=null)db.settings.auto=!!b.auto;
      if(b.support!=null)db.settings.support=cleanTg(b.support);if(b.channel!=null)db.settings.channel=cleanTg(b.channel);
      if(b.linkExtra!=null){const v=cleanExtra(b.linkExtra);if(v===null)return J(res,{e:'فقط حروف انگلیسی، عدد و = & , : . - _ % / + مجازه'},400);db.settings.linkExtra=v}
      if(b.subInfo!=null)db.settings.subInfo=!!b.subInfo;if(b.locName!=null)db.settings.locName=keepName(b.locName);if(NAME_STYLES.includes(b.nameStyle))db.settings.nameStyle=b.nameStyle;
      if(b.sshOn!=null){db.settings.sshOn=!!b.sshOn;if(db.settings.sshOn&&ssh2){ensureSsh();sshInit()}}
      if(b.addr!=null)db.settings.addr=cleanAddr(String(b.addr).trim());
      if(b.host!=null){const v=String(b.host).trim().toLowerCase().replace(/^https?:\/\//,'').split('/')[0];if(v&&!/^[a-z0-9.-]{3,253}$/.test(v))return J(res,{e:'دامنه نامعتبره (مثل sub.example.com)'},400);db.settings.host=v?cleanHost(v):'';}
      if(b.fallback!=null){const v=String(b.fallback).trim().toLowerCase().replace(/^https?:\/\//,'').split('/')[0];if(v&&!/^[a-z0-9.-]{3,253}$/.test(v))return J(res,{e:'دامنه جایگزین نامعتبره'},400);db.settings.fallback=v?cleanHost(v):'';}
      if(b.plans!=null){if(!Array.isArray(b.plans))return J(res,{e:'پلن نامعتبره'},400);db.settings.plans=b.plans.filter(p=>p&&p.name).slice(0,20).map(p=>({name:String(p.name).slice(0,30),gb:Math.max(0,+p.gb||0),days:Math.max(0,Math.floor(+p.days||0)),maxDev:Math.max(0,Math.floor(+p.maxDev||0))}));}
      if(b.payCard!=null)db.settings.payCard=String(b.payCard).replace(/[^\d\s-]/g,'').slice(0,32);
      if(b.payUrl!=null){const v=String(b.payUrl).trim().slice(0,200);if(v&&!/^https?:\/\/.{4,}$/.test(v))return J(res,{e:'لینک پرداخت باید با http شروع بشه'},400);db.settings.payUrl=v}
      if(b.botUser!=null)db.settings.botUser=cleanTg(b.botUser);
      if(b.botToken)db.settings.botToken=String(b.botToken).trim().slice(0,120);if(b.clearBotToken)delete db.settings.botToken;
      if(b.scanAuto!=null)db.settings.scanAuto=!!b.scanAuto;
      if(b.scanEveryH!=null)db.settings.scanEveryH=Math.max(1,Math.min(72,Math.floor(+b.scanEveryH||12)));
      if(b.locHealth!=null)db.settings.locHealth=!!b.locHealth;
      if(b.locHealthMin!=null)db.settings.locHealthMin=Math.max(5,Math.min(720,Math.floor(+b.locHealthMin||30)));
      if(b.sources!=null){if(!Array.isArray(b.sources))return J(res,{e:'سورس نامعتبره'},400);
        const vs=b.sources.map(s=>String(s).trim().slice(0,300)).filter(s=>/^https?:\/\/.{6,}$/.test(s)).slice(0,10);db.settings.sources=vs;}
      if(b.pass){if(String(b.pass).length<6)return J(res,{e:'رمز حداقل ۶ کاراکتر'},400);db.settings.pass=String(b.pass);db.secret=crypto.randomBytes(24).toString('hex');
        res.setHeader('Set-Cookie',sessCookie(req,mkToken()))}
      save();return J(res,{ok:1})}
    if(u==='/api/update/check'){try{const L=await latest(),cur=curVersion();return J(res,{current:cur,latest:L,available:L.sha!==cur.sha})}catch(e){return J(res,{e:e.message},502)}}
    if(u==='/api/update/apply'&&req.method==='POST'){try{const L=await applyUpdate();J(res,{ok:1,latest:L});restartApp();return}catch(e){return J(res,{e:e.message},500)}}
    if(u==='/api/scan'){if(!CF.length)return J(res,{e:'لیست ساب‌نت موجود نیست'},400);
      const sni=/^[\w.-]{3,100}$/.test(b.sni||'')?b.sni:'speed.cloudflare.com';return J(res,await scan(sni,Math.min(200,Math.max(10,+b.count||60))))}
    if(u==='/api/diag')return J(res,await runDiag(effHost(req,h)));
    if(u==='/api/nodes'&&req.method==='GET')return J(res,{nodes:db.nodes.map(nodePub)});
    if(u==='/api/nodes'&&req.method==='POST'){
      const dom=cleanDomain(b.domain);if(dom===null)return J(res,{e:'دامنه نامعتبره'},400);
      const cc=String(b.cc||'').trim().toUpperCase();if(cc&&!/^[A-Z]{2}$/.test(cc))return J(res,{e:'کد کشور باید دو حرف باشه (مثل NL)'},400);
      if(db.nodes.length>=30)return J(res,{e:'حداکثر ۳۰ نود'},400);
      const token=crypto.randomBytes(24).toString('hex');
      const n={id:'N'+Date.now().toString(36),name:keepName(b.name)||'Node',domain:dom,cc,ccManual:!!cc,label:keepName(b.label),on:true,all:!!b.all,tokenHash:sha256(token),created:Date.now()};
      db.nodes.push(n);save();return J(res,{ok:1,node:nodePub(n),token,master:'https://'+effHost(req,h)})}
    if(u==='/api/node/update'){const n=db.nodes.find(v=>v.id===b.id);if(!n)return J(res,{e:1},404);let token=null;
      if(b.name!=null)n.name=keepName(b.name)||n.name;if(b.label!=null)n.label=keepName(b.label);
      if(b.domain!=null){const d=cleanDomain(b.domain);if(d===null)return J(res,{e:'دامنه نامعتبره'},400);n.domain=d;n.up=null;n.ms=null}
      if(b.cc!=null){const c=String(b.cc).trim().toUpperCase();if(c&&!/^[A-Z]{2}$/.test(c))return J(res,{e:'کد کشور باید دو حرف باشه'},400);n.cc=c;n.ccManual=!!c}
      if(b.on!=null)n.on=!!b.on;if(b.all!=null)n.all=!!b.all;
      if(b.regen){token=crypto.randomBytes(24).toString('hex');n.tokenHash=sha256(token)}
      save();return J(res,{ok:1,node:nodePub(n),token,master:'https://'+effHost(req,h)})}
    if(u==='/api/node/del'){db.nodes=db.nodes.filter(v=>v.id!==b.id);save();return J(res,{ok:1})}
    if(u==='/api/locs')return J(res,{locs:db.locs||[],sources:srcList(),defaults:DEFAULT_SOURCES,
      health:{on:db.settings.locHealth!==false,everyMin:Math.max(5,Math.min(720,+db.settings.locHealthMin||30)),checkedAt:lastLocCheck}});
    if(u==='/api/loc/add'){const host=String(b.host||'').trim().toLowerCase().replace(/^https?:\/\//,'').split(/[/:]/)[0];
      const port=Math.floor(+b.port||0);
      if(!/^[a-z0-9.-]{2,253}$/.test(host)||port<1||port>65535)return J(res,{e:'هاست یا پورت نامعتبره'},400);
      db.locs=db.locs||[];
      if(db.locs.some(l=>l.host===host&&+l.port===port))return J(res,{e:'این پروکسی قبلاً اضافه شده'},400);
      if(db.locs.length>=100)return J(res,{e:'حداکثر ۱۰۰ لوکیشن'},400);
      const user=String(b.user||'').slice(0,64),pass=String(b.pass||'').slice(0,64);
      let proto=(b.proto==='http'||b.proto==='socks5')?b.proto:'',ms=null,why=null,xip='',xcc='';
      if(proto){const t=proto==='http'?await httpTest(host,port,user,pass,8000):await socksTest(host,port,user,pass,8000);
        if(t.ms==null)return J(res,{e:'پروکسی جواب نداد ('+(t.why||'timeout')+')'},400);ms=t.ms;xip=t.ip||'';xcc=t.cc||''}
      else{const d=await detectProto(host,port,user,pass);if(!d.proto)return J(res,{e:'هیچ پروتکلی جواب نداد (socks5/http)'},400);proto=d.proto;ms=d.ms;xip=d.ip||'';xcc=d.cc||''}
      const xcountry=xcc?cleanLoc(ccName(xcc)):'';
      db.locs.push({id:'L'+Date.now().toString(36),label:cleanLoc(b.label)||xcountry||host,host,port,user,pass,proto,on:true,ms,why,at:Date.now(),egress:xip,cc:xcc,country:xcountry});
      save();restartSoon();return J(res,{ok:1,proto,ms})}
    if(u==='/api/loc/update'){const l=(db.locs||[]).find(v=>v.id===b.id);if(!l)return J(res,{e:1},404);
      if(b.on!=null)l.on=!!b.on;if(b.label!=null)l.label=cleanLoc(b.label)||l.label;save();restartSoon();return J(res,{ok:1})}
    if(u==='/api/loc/del'){db.locs=(db.locs||[]).filter(v=>v.id!==b.id);
      db.inbounds.forEach(i=>{if(i.egress===b.id)delete i.egress});save();restartSoon();return J(res,{ok:1})}
    if(u==='/api/loc/test'){const l=(db.locs||[]).find(v=>v.id===b.id);if(!l)return J(res,{e:1},404);
      const d=await detectProto(l.host,l.port,l.user,l.pass,8000);
      l.at=Date.now();
      if(!d.proto){l.ms=null;l.why=d.why;save();return J(res,{ok:1,ms:null,why:d.why})}
      l.proto=d.proto;l.ms=d.ms;l.why=null;
      const g=await geoFill(await socksEgress(l.host,l.port,l.user,l.pass,l.proto).catch(()=>({})),l.host,l.port,l.user,l.pass,l.proto);
      if(g&&g.ip){l.egress=g.ip;l.country=g.country||'';l.cc=g.cc||'';
        if(/^(?:\uD83C\uDF10 )?[\d.]+(?::\d+)?$/.test(l.label||''))l.label=(g.country||l.host)}
      save();return J(res,{ok:1,ms:l.ms,proto:l.proto,why:null,egress:l.egress||null,country:l.country||null,cc:l.cc||null})}
    if(u==='/api/loc/fetch'){
      // 3 stages: (A) cheap TCP ping to thousands of random candidates, (B) real end-to-end probe for the closest ones, (C) re-check the winners
      const T0=Date.now(),dl=T0+65000;
      const cc=(Array.isArray(b.countries)?b.countries:String(b.countries||'').split(/[\s,;]+/)).map(x=>String(x).trim().toUpperCase()).filter(x=>/^[A-Z]{2}$/.test(x)).slice(0,6);
      const urls=cc.length?cc.map(c=>'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/'+c+'/data.txt'):(Array.isArray(b.urls)&&b.urls.length?b.urls:srcList()).slice(0,10);
      const clamp=(v,lo,hi,d)=>Math.min(hi,Math.max(lo,Math.floor(+v||d)));
      const max=clamp(b.max,1,30,10),maxMs=clamp(b.maxMs,150,5000,800),tries=clamp(b.tries,100,1500,700);
      const all=await fetchProxies(urls);
      const have=new Set((db.locs||[]).map(l=>l.host+':'+l.port));
      const fresh=shuffle(all.filter(p=>!have.has(p.host+':'+p.port))).slice(0,tries);
      const A=[];{const q=fresh.slice(),endA=T0+22000;
        await Promise.all(Array.from({length:150},async()=>{while(q.length&&Date.now()<endA){const p=q.shift();const ms=await tcpPing(p.host,p.port,1800);if(ms!=null)A.push({...p,tcp:ms})}}))}
      A.sort((x,y)=>x.tcp-y.tcp);
      const good=[],fails={};{const q=A.slice(0,70);
        await Promise.all(Array.from({length:20},async()=>{while(q.length&&Date.now()<dl-14000){const p=q.shift();const r=await detectProto(p.host,p.port,p.user,p.pass,6000);
          if(r.proto&&r.ms<=maxMs)good.push({...p,proto:r.proto,ms:r.ms,ip:r.ip,cc:r.cc});
          else{const k=r.proto?'slow':(r.why||'conn');fails[k]=(fails[k]||0)+1}}}))}
      good.sort((x,y)=>x.ms-y.ms);
      const keep=[];{const top=good.slice(0,Math.min(good.length,max*2));
        await Promise.all(top.map(async g=>{const r=await detectProto(g.host,g.port,g.user,g.pass,7000);
          if(r.proto&&r.ms<=maxMs*1.3){g.ms=Math.round((g.ms+r.ms)/2);g.proto=r.proto;if(r.cc){g.cc=r.cc;g.ip=r.ip}keep.push(g)}else fails.unstable=(fails.unstable||0)+1}))}
      keep.sort((x,y)=>x.ms-y.ms);
      db.locs=db.locs||[];const added=[];
      for(const g of keep.slice(0,max)){if(db.locs.length>=100)break;
        const country=g.cc?cleanLoc(ccName(g.cc)):'';
        const nl={id:'L'+Date.now().toString(36)+Math.floor(Math.random()*99),label:g.cc?(country||g.host):g.host,on:true,host:g.host,port:g.port,user:g.user,pass:g.pass,proto:g.proto,ms:g.ms,at:Date.now(),egress:g.ip||'',country,cc:g.cc||''};
        db.locs.push(nl);added.push(nl)}
      save();restartSoon();
      return J(res,{ok:1,tested:all.length,checked:fresh.length,reachable:A.length,probed:Math.min(A.length,70),added:added.length,maxMs,secs:Math.round((Date.now()-T0)/1000),fails,
        list:added.slice(0,30).map(l=>({host:l.host,port:l.port,proto:l.proto,ms:l.ms,country:l.country||'',cc:l.cc||'',egress:l.egress||''}))})}
    if(u==='/api/loc/inbound'){const l=(db.locs||[]).find(v=>v.id===b.id);if(!l)return J(res,{e:'لوکیشن پیدا نشد'},404);
      let pth,n=0;do{pth='/'+Math.random().toString(36).slice(2,9);n++}while(db.inbounds.some(i=>i.path===pth)&&n<20);
      if(db.inbounds.some(i=>i.path===pth))return J(res,{e:'مسیر تکراری شد، دوباره بزن'},400);
      const port=Math.max(10000,...db.inbounds.map(i=>i.port))+1;
      const nm=String('Proxy · '+(l.label||l.host)).slice(0,30);
      db.inbounds.push({id:'i'+Date.now().toString(36),port,on:true,proto:'vless',net:'ws',path:pth,name:nm,loc:'',egress:l.id});
      save();restartSoon();return J(res,{ok:1,name:nm})}
  }
  res.writeHead(404);res.end('Not found');
}
SERVER.on('upgrade',(req,sock,head)=>{try{
  const p=db.inbounds.find(x=>x.on&&(req.url===x.path||req.url.startsWith(x.path+'?')||req.url.startsWith(x.path+'/')));
  if(!p){if(sshWant(req))return sshAttach(req,sock,head);return sock.destroy()}
  const cip=clientIp(req),up=net.connect(p.port,'127.0.0.1',()=>{
    let s=req.method+' '+req.url+' HTTP/1.1\r\n';
    for(let i=0;i<req.rawHeaders.length;i+=2){const k=req.rawHeaders[i].toLowerCase();if(k==='x-forwarded-for'||k==='x-real-ip'||k==='forwarded')continue;s+=req.rawHeaders[i]+': '+req.rawHeaders[i+1]+'\r\n'}
    up.write(s+'X-Forwarded-For: '+cip+'\r\n\r\n');if(head&&head.length)up.write(head);sock.pipe(up);up.pipe(sock)});
  conns++;let done=false;const end=()=>{if(!done){done=true;conns--}sock.destroy();up.destroy()};
  sock.setNoDelay(true);up.setNoDelay(true);sock.setKeepAlive(true,30000);
  up.on('error',end);sock.on('error',end);up.on('close',end);sock.on('close',end);
}catch(e){try{sock.destroy()}catch(_){}}
}).listen(PORT,()=>console.log('BATAMN on',PORT));
