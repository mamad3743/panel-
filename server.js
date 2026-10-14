// BATAMN v3 — Xray panel: users (traffic/expiry), inbounds, scanner, settings — single HTTP port
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
let db;
try{db=JSON.parse(fs.readFileSync(DBF))}catch(e){
  let old=[];try{old=JSON.parse(fs.readFileSync(OLD))}catch(_){}
  db={secret:crypto.randomBytes(24).toString('hex'),settings:{addr:'',theme:'knight',pass:process.env.ADMIN_PASS||'admin'},
    inbounds:DEF_IN.map((x,i)=>({id:'i'+(i+1),port:10000+i,on:true,...x})),
    users:old.length?old.map(u=>({limit:0,exp:0,used:0,note:'',...u})):[{id:crypto.randomUUID(),name:'default',on:true,created:Date.now(),limit:0,exp:0,used:0,note:''}]};
  save();
}
function save(){fs.writeFileSync(DBF,JSON.stringify(db,null,1))}
const F=n=>fs.readFileSync(path.join(__dirname,n));
const STATIC={'/':['index.html','text/html; charset=utf-8'],'/style.css':['style.css','text/css'],'/app.js':['app.js','application/javascript'],'/bg.svg':['bg.svg','image/svg+xml']};
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
const sig=()=>JSON.stringify([db.users.filter(isActive).map(u=>u.id),db.inbounds.filter(i=>i.on).map(i=>[i.id,i.proto,i.net,i.path,i.port])]);

// ---------- xray ----------
let xray=null,lastSig='',rt=null;
function buildCfg(){
  const act=db.users.filter(isActive),cl=act.length?act:[{id:crypto.randomUUID()}];
  const inb=db.inbounds.filter(i=>i.on).map(i=>{
    const settings=i.proto==='vless'?{clients:cl.map(u=>({id:u.id,email:u.id})),decryption:'none'}
      :i.proto==='vmess'?{clients:cl.map(u=>({id:u.id,alterId:0,email:u.id}))}
      :{clients:cl.map(u=>({password:u.id,email:u.id}))};
    const ss={network:i.net};ss[i.net==='ws'?'wsSettings':'httpupgradeSettings']={path:i.path};
    return{tag:i.id,listen:'127.0.0.1',port:i.port,protocol:i.proto,settings,streamSettings:ss,sniffing:{enabled:true,destOverride:['http','tls']}};
  });
  inb.push({tag:'api',listen:'127.0.0.1',port:10085,protocol:'dokodemo-door',settings:{address:'127.0.0.1'}});
  return{log:{loglevel:'warning'},api:{tag:'api',services:['StatsService']},stats:{},
    dns:{servers:['1.1.1.1','8.8.8.8'],queryStrategy:'UseIPv4'},
    policy:{levels:{0:{handshake:4,connIdle:300,statsUserUplink:true,statsUserDownlink:true}}},
    routing:{rules:[{type:'field',inboundTag:['api'],outboundTag:'api'}]},
    inbounds:inb,outbounds:[{protocol:'freedom',settings:{domainStrategy:'UseIPv4'}},{protocol:'blackhole',tag:'block'}]};
}
function startXray(){
  lastSig=sig();const f=path.join(DIR,'config.json');fs.writeFileSync(f,JSON.stringify(buildCfg()));
  if(xray){xray.removeAllListeners('exit');xray.kill()}
  xray=spawn('xray',['run','-c',f],{stdio:'inherit'});
  xray.on('exit',()=>setTimeout(startXray,2000));
}
function restartSoon(){clearTimeout(rt);rt=setTimeout(async()=>{await poll();startXray()},400)}
function poll(){return new Promise(r=>{
  execFile('xray',['api','statsquery','-s','127.0.0.1:10085','-pattern','user>>>','-reset'],{timeout:5000},(e,out)=>{
    if(e||!out)return r();
    try{let ch=false;(JSON.parse(out).stat||[]).forEach(s=>{const m=/^user>>>(.+)>>>traffic>>>(uplink|downlink)$/.exec(s.name);if(!m)return;
      const u=db.users.find(x=>x.id===m[1]);if(u){const d=+s.value||0;u.used+=d;addTraffic(u,d);ch=true}});if(ch){prune();save()}}catch(_){}
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

// ---------- links ----------
const cleanAddr=a=>a&&/^[\w.\-:\[\]]{1,100}$/.test(a)?a:'';
function linksFor(u,h,addr){
  const a=addr||db.settings.addr||h,q='security=tls&sni='+h+'&fp=chrome&alpn=http%2F1.1&host='+h;
  return db.inbounds.filter(i=>i.on).map(i=>{
    const nm='BATAMN-'+u.name+'-'+i.name.replace(/\s*·\s*/g,'-'),p=encodeURIComponent(i.path);let l;
    if(i.proto==='vmess')l='vmess://'+Buffer.from(JSON.stringify({v:'2',ps:nm,add:a,port:'443',id:u.id,aid:'0',scy:'auto',net:i.net,type:'none',host:h,path:i.path,tls:'tls',sni:h,alpn:'http/1.1',fp:'chrome'})).toString('base64');
    else if(i.proto==='trojan')l='trojan://'+u.id+'@'+a+':443?'+q+'&type='+i.net+'&path='+p+'#'+encodeURIComponent(nm);
    else l='vless://'+u.id+'@'+a+':443?encryption=none&'+q+'&type='+i.net+'&path='+p+'#'+encodeURIComponent(nm);
    return{k:i.id,n:i.name,l};});
}
function qrSvg(t){
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

// ---------- auth ----------
const sign=e=>crypto.createHmac('sha256',db.secret).update(String(e)).digest('hex');
const mkToken=()=>{const e=Date.now()+30*864e5;return e+'.'+sign(e)};
const authed=req=>{const c=(req.headers.cookie||'').split(/;\s*/).find(x=>x.startsWith('bt='));if(!c)return false;
  const[e,s]=c.slice(3).split('.');return !!s&&+e>Date.now()&&crypto.timingSafeEqual(Buffer.from(sign(e)),Buffer.from(s.padEnd(64,'x').slice(0,64)))};
const fails={};
const hostOf=req=>process.env.PUBLIC_HOST||process.env.RAILWAY_PUBLIC_DOMAIN||(req.headers['x-forwarded-host']||req.headers.host||'').split(':')[0];
const J=(res,o,c=200)=>{res.writeHead(c,{'content-type':'application/json'});res.end(JSON.stringify(o))};
const body=req=>new Promise(r=>{let b='';req.on('data',c=>{b+=c;if(b.length>1e5)req.destroy()});req.on('end',()=>{try{r(JSON.parse(b||'{}'))}catch(e){r({})}})});
const cleanTg=x=>{x=String(x||'').trim().replace(/^https?:\/\/t\.me\//,'').replace(/^@/,'');return /^[A-Za-z0-9_]{3,40}$/.test(x)?x:''};
const contact=()=>({support:db.settings.support!=null?db.settings.support:'mamadi1048',channel:db.settings.channel!=null?db.settings.channel:'editmamad_e'});
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const cleanName=s=>String(s||'user').slice(0,30).replace(/[^\w\u0600-\u06FF -]/g,'').trim()||'user';
const pubUser=(u,h,addr,withLinks)=>({days:dates14().map(d=>(u.days||{})[d]||0),id:u.id,name:u.name,on:u.on,created:u.created,limit:u.limit,exp:u.exp,used:u.used,note:u.note,status:status(u),...(withLinks?{links:linksFor(u,h,addr)}:{})});

http.createServer(async(req,res)=>{
  const U=new URL(req.url,'http://x'),u=U.pathname,h=hostOf(req),addr=cleanAddr(U.searchParams.get('addr'));
  if(FILES[u]&&req.method==='GET'){const bufr=u==='/'?Buffer.from(FILES[u].toString().replace('__THEME__',db.settings.theme||'knight')):FILES[u];return res.writeHead(200,{'content-type':STATIC[u][1],'cache-control':u==='/bg.svg'?'public,max-age=86400':'no-cache'}),res.end(bufr)}
  if(u.startsWith('/fonts/')){const f=fontFile(u.slice(7));if(!f){res.writeHead(404);return res.end()}res.writeHead(200,{'content-type':'font/woff2','cache-control':'public,max-age=31536000,immutable'});return fs.createReadStream(f).pipe(res)}
  if(u==='/health')return res.end('ok');
  if(u==='/qr'){const s=qrSvg((U.searchParams.get('d')||'').slice(0,1500));return res.writeHead(s?200:404,{'content-type':'image/svg+xml'}),res.end(s)}
  if(u.startsWith('/sub/')){
    const x=db.users.find(v=>v.id===u.slice(5)),html=(req.headers.accept||'').includes('text/html')&&!U.searchParams.has('raw');
    if(!x){res.writeHead(404,{'content-type':'text/plain'});return res.end('Not found')}
    const st=status(x),L=st==='active'?linksFor(x,h,addr):[];
    if(!html){
      if(st!=='active'){res.writeHead(403,{'content-type':'text/plain'});return res.end(st)}
      res.writeHead(200,{'content-type':'text/plain; charset=utf-8','profile-title':'BATAMN','profile-update-interval':'12',...(contact().support?{'support-url':'https://t.me/'+contact().support}:{}),...(contact().channel?{'profile-web-page-url':'https://t.me/'+contact().channel}:{}),
        'subscription-userinfo':'upload=0; download='+x.used+'; total='+x.limit+'; expire='+(x.exp?Math.floor(x.exp/1000):0)});
      return res.end(Buffer.from(L.map(i=>i.l).join('\n')).toString('base64'));
    }
    const subUrl='https://'+h+'/sub/'+x.id+(addr?'?addr='+encodeURIComponent(addr):'');
    const data={contact:contact(),sub:subUrl,status:st,used:x.used,limit:x.limit,exp:x.exp,links:L.map(i=>({n:i.n,l:i.l,qr:qrSvg(i.l)}))};
    const page=SUB.replace('__THEME__',db.settings.theme||'knight').replace(/__NAME__/g,()=>esc(x.name)).replace('__QR__',()=>st==='active'?qrSvg(subUrl):'').replace('__DATA__',()=>JSON.stringify(data).replace(/</g,'\\u003c'));
    return res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store'}),res.end(page);
  }
  if(u==='/api/login'&&req.method==='POST'){
    const ip=(req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0],f=fails[ip]||{n:0,t:Date.now()};
    if(Date.now()-f.t>600000){f.n=0;f.t=Date.now()}
    if(f.n>=8)return J(res,{e:'تلاش زیاد. بعداً امتحان کن'},429);
    const b=await body(req);
    if(typeof b.pass==='string'&&b.pass===db.settings.pass){delete fails[ip];res.setHeader('Set-Cookie','bt='+mkToken()+'; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=2592000');return J(res,{ok:1})}
    f.n++;fails[ip]=f;return J(res,{e:'رمز اشتباهه'},401);
  }
  if(u==='/api/logout'){res.setHeader('Set-Cookie','bt=; Path=/; Max-Age=0');return J(res,{ok:1})}
  if(u.startsWith('/api/')){
    if(!authed(req))return J(res,{e:1},401);
    if(u==='/api/me')return J(res,{ok:1});
    if(u==='/api/sys')return J(res,{cpu:cpuPct,cores:+cpuCores.toFixed(1),mem:memInfo(),disk:diskInfo(),net:{rx:NS.rx,tx:NS.tx,rxs:NS.rxs,txs:NS.txs},
      pup:process.uptime(),load:os.loadavg(),conns,region:process.env.RAILWAY_REPLICA_REGION||process.env.RAILWAY_REGION||'—',
      xray:{on:!!(xray&&xray.exitCode===null),mem:xrayMem()}});
    if(u==='/api/state'){
      const D=dates14();return J(res,{host:h,settings:{addr:db.settings.addr,theme:db.settings.theme||'knight',...contact(),...repoCfg(),auto:!!db.settings.auto,hasToken:!!db.settings.token},version:curVersion(),inbounds:db.inbounds,daily:{dates:D,total:D.map(d=>(db.daily||{})[d]||0)},
        users:db.users.map(x=>pubUser(x,h,addr,true)),totalUsed:db.users.reduce((a,x)=>a+x.used,0)});
    }
    const b=await body(req);
    if(u==='/api/users'){db.users.push({id:crypto.randomUUID(),name:cleanName(b.name),on:true,created:Date.now(),
        limit:Math.max(0,+b.gb||0)*GB,exp:b.days>0?Date.now()+b.days*864e5:0,used:0,note:String(b.note||'').slice(0,100)});save();restartSoon();return J(res,{ok:1})}
    if(u==='/api/user/update'){const x=db.users.find(v=>v.id===b.id);if(!x)return J(res,{e:1},404);
      if(b.name!=null)x.name=cleanName(b.name);if(b.gb!=null)x.limit=Math.max(0,+b.gb||0)*GB;if(b.exp!=null)x.exp=Math.max(0,+b.exp||0);
      if(b.note!=null)x.note=String(b.note).slice(0,100);if(b.on!=null)x.on=!!b.on;if(b.reset)x.used=0;save();restartSoon();return J(res,{ok:1})}
    if(u==='/api/user/del'){db.users=db.users.filter(v=>v.id!==b.id);save();restartSoon();return J(res,{ok:1})}
    if(u==='/api/inbounds'){
      const pth=String(b.path||'').trim();
      if(!/^\/[A-Za-z0-9_-]{1,30}$/.test(pth))return J(res,{e:'مسیر نامعتبر (مثلاً /abc)'},400);
      if(db.inbounds.some(i=>i.path===pth))return J(res,{e:'این مسیر قبلاً استفاده شده'},400);
      if(!['vless','vmess','trojan'].includes(b.proto)||!['ws','httpupgrade'].includes(b.net))return J(res,{e:'نامعتبر'},400);
      const port=Math.max(10000,...db.inbounds.map(i=>i.port))+1;
      db.inbounds.push({id:'i'+Date.now().toString(36),port,on:true,proto:b.proto,net:b.net,path:pth,name:String(b.name||(b.proto.toUpperCase()+' · '+b.net.toUpperCase())).slice(0,30)});
      save();restartSoon();return J(res,{ok:1})}
    if(u==='/api/inbound/update'){const i=db.inbounds.find(v=>v.id===b.id);if(!i)return J(res,{e:1},404);
      if(b.on!=null)i.on=!!b.on;if(b.name)i.name=String(b.name).slice(0,30);save();restartSoon();return J(res,{ok:1})}
    if(u==='/api/inbound/del'){if(db.inbounds.length<=1)return J(res,{e:'حداقل یک اینباند لازمه'},400);db.inbounds=db.inbounds.filter(v=>v.id!==b.id);save();restartSoon();return J(res,{ok:1})}
    if(u==='/api/settings'){
      if(['knight','gotham','joker'].includes(b.theme))db.settings.theme=b.theme;
      if(b.repo!=null){const v=String(b.repo).trim().replace(/^https?:\/\/github\.com\//,'').replace(/\.git$/,'').replace(/\/$/,'');if(v&&!/^[\w.-]+\/[\w.-]+$/.test(v))return J(res,{e:'ریپو باید به شکل owner/repo باشه'},400);db.settings.repo=v}
      if(b.branch!=null){const v=String(b.branch).trim();if(v&&!/^[\w./-]{1,60}$/.test(v))return J(res,{e:'برنچ نامعتبره'},400);db.settings.branch=v}
      if(b.token)db.settings.token=String(b.token).trim().slice(0,200);if(b.clearToken)delete db.settings.token;
      if(b.auto!=null)db.settings.auto=!!b.auto;
      if(b.support!=null)db.settings.support=cleanTg(b.support);if(b.channel!=null)db.settings.channel=cleanTg(b.channel);
      if(b.addr!=null)db.settings.addr=cleanAddr(String(b.addr).trim());
      if(b.pass){if(String(b.pass).length<6)return J(res,{e:'رمز حداقل ۶ کاراکتر'},400);db.settings.pass=String(b.pass);db.secret=crypto.randomBytes(24).toString('hex');
        res.setHeader('Set-Cookie','bt='+mkToken()+'; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=2592000')}
      save();return J(res,{ok:1})}
    if(u==='/api/update/check'){try{const L=await latest(),cur=curVersion();return J(res,{current:cur,latest:L,available:L.sha!==cur.sha})}catch(e){return J(res,{e:e.message},502)}}
    if(u==='/api/update/apply'&&req.method==='POST'){try{const L=await applyUpdate();J(res,{ok:1,latest:L});restartApp();return}catch(e){return J(res,{e:e.message},500)}}
    if(u==='/api/scan'){if(!CF.length)return J(res,{e:'لیست ساب‌نت موجود نیست'},400);
      const sni=/^[\w.-]{3,100}$/.test(b.sni||'')?b.sni:'speed.cloudflare.com';return J(res,await scan(sni,Math.min(200,Math.max(10,+b.count||60))))}
  }
  res.writeHead(404);res.end('Not found');
}).on('upgrade',(req,sock,head)=>{
  const p=db.inbounds.find(x=>x.on&&(req.url===x.path||req.url.startsWith(x.path+'?')||req.url.startsWith(x.path+'/')));
  if(!p)return sock.destroy();
  const up=net.connect(p.port,'127.0.0.1',()=>{
    let s=req.method+' '+req.url+' HTTP/1.1\r\n';
    for(let i=0;i<req.rawHeaders.length;i+=2)s+=req.rawHeaders[i]+': '+req.rawHeaders[i+1]+'\r\n';
    up.write(s+'\r\n');if(head&&head.length)up.write(head);sock.pipe(up);up.pipe(sock)});
  conns++;let done=false;const end=()=>{if(!done){done=true;conns--}sock.destroy();up.destroy()};
  sock.setNoDelay(true);up.setNoDelay(true);sock.setKeepAlive(true,30000);
  up.on('error',end);sock.on('error',end);up.on('close',end);sock.on('close',end);
}).listen(PORT,()=>console.log('BATAMN on',PORT));
