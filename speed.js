/* BATAMN speed test: ping/jitter, download, upload against this server (shared by panel and subscription page) */
var SpeedTest=(function(){
  function down(q,on,secs){return(async function(){
    var ac=new AbortController(),t0=performance.now(),got=0,last=t0,lb=0;
    try{var r=await fetch('/speed/down?'+q+'&bytes=60000000&r='+Math.random(),{cache:'no-store',signal:ac.signal});
      if(!r.ok)throw new Error('auth');var rd=r.body.getReader();
      while(true){var x=await rd.read();if(x.done)break;got+=x.value.length;var n=performance.now();
        if(n-last>250){on('down',(got-lb)*8/((n-last)/1000)/1e6);last=n;lb=got}
        if(n-t0>secs*1000){ac.abort();break}}
    }catch(e){if(e.message==='auth')throw e}
    return got*8/((performance.now()-t0)/1000)/1e6})()}
  function up(q,on,secs){return new Promise(function(res){
    var x=new XMLHttpRequest(),t0=performance.now(),ld=0,data=new Uint8Array(12*1024*1024);
    var fin=function(){res(ld*8/((performance.now()-t0)/1000)/1e6)};
    x.open('POST','/speed/up?'+q+'&r='+Math.random());
    x.upload.onprogress=function(e){ld=e.loaded;var el=(performance.now()-t0)/1000;if(el>.3)on('up',ld*8/el/1e6);if(el>secs)x.abort()};
    x.onload=fin;x.onerror=fin;x.onabort=fin;x.send(data)})}
  async function run(q,on){
    var out={};
    try{
      on('stage','ping');var t=[];
      for(var i=0;i<10;i++){var s=performance.now(),r=await fetch('/speed/ping?'+q+'&r='+Math.random(),{cache:'no-store'});
        if(!r.ok)throw new Error('auth');t.push(performance.now()-s);if(i>0)on('ping',Math.min.apply(null,t.slice(1)))}
      t.shift();out.ping=Math.min.apply(null,t);var j=0;for(i=1;i<t.length;i++)j+=Math.abs(t[i]-t[i-1]);out.jitter=j/Math.max(1,t.length-1);
      on('ping',out.ping);on('jitter',out.jitter);
      on('stage','down');out.down=await down(q,on,6);on('down',out.down);
      on('stage','up');out.up=await up(q,on,5);on('up',out.up);
    }catch(e){out.err=e.message||'error'}
    on('stage','done');return out}
  function bind(q){
    var g=function(i){return document.getElementById(i)},b=g('s_go');if(!b)return;
    var M={ping:['s_p',' ms',0],jitter:['s_j',' ms',0],down:['s_d',' Mbps',1],up:['s_u',' Mbps',1]},ST={ping:'PING…',down:'DOWNLOAD…',up:'UPLOAD…',done:''};
    b.onclick=function(){if(b.disabled)return;b.disabled=true;b.innerHTML='<span class="spin"></span>در حال تست...';
      ['s_p','s_j','s_d','s_u'].forEach(function(i){g(i).textContent='—'});
      run(q,function(k,v){if(M[k])g(M[k][0]).textContent=v.toFixed(M[k][2])+M[k][1];if(k=='stage')g('sst').textContent=ST[v]}).then(function(o){
        b.disabled=false;b.textContent='تست دوباره';if(o.err)g('sst').textContent='خطا در تست'})}}
  return{run:run,bind:bind}})();
