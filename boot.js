// BATAMN supervisor: runs the baked app, or a newer copy installed by the in-panel GitHub updater (rolls back if it keeps crashing)
const {spawn}=require('child_process'),fs=require('fs'),path=require('path');
const BASE=__dirname;let DIR=process.env.DATA_DIR||'/data';
try{fs.mkdirSync(DIR,{recursive:true});fs.accessSync(DIR,fs.constants.W_OK)}catch(e){DIR=path.join(BASE,'data');fs.mkdirSync(DIR,{recursive:true})}
const OV=path.join(DIR,'app'),num=f=>{try{return +fs.readFileSync(f,'utf8').trim()||0}catch(e){return 0}};
let child=null,bad=0,stop=false;
const useOverlay=()=>fs.existsSync(path.join(OV,'server.js'))&&num(path.join(OV,'INSTALL_TS'))>num(path.join(BASE,'BUILD_TS'));
function run(){
  const ov=useOverlay(),dir=ov?OV:BASE,t0=Date.now();
  console.log('[boot] starting',ov?'updated copy':'image copy');
  child=spawn(process.execPath,['server.js'],{cwd:dir,stdio:'inherit',env:{...process.env,BATAMN_DATA:DIR,NODE_PATH:path.join(BASE,'node_modules'),BATAMN_OVERLAY:ov?'1':'0'}});
  child.on('exit',code=>{if(stop)return;
    if(ov&&code!==42&&Date.now()-t0<20000){if(++bad>=3){console.log('[boot] update looks broken, rolling back');fs.rmSync(OV,{recursive:true,force:true});bad=0}}else bad=0;
    setTimeout(run,code===42?200:1500)});
}
['SIGTERM','SIGINT'].forEach(s=>process.on(s,()=>{stop=true;if(child)child.kill(s);setTimeout(()=>process.exit(0),500)}));
run();
