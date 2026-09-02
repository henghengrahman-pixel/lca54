const express=require('express');
const path=require('path');
const fs=require('fs');
const crypto=require('crypto');
const {Store}=require('./store');
const {Telegram,esc}=require('./telegram');

const app=express();
app.set('trust proxy',1);
const PORT=Number(process.env.PORT||8080);
function envValue(name, fallback=''){
  let v=process.env[name];
  if(v==null) return fallback;
  v=String(v).replace(/[\r\n]+$/g,'');
  if((v.startsWith('\"')&&v.endsWith('\"'))||(v.startsWith("'")&&v.endsWith("'"))) v=v.slice(1,-1);
  return v;
}
const DATA_DIR=envValue('DATA_DIR',path.join(__dirname,'..','data'));
const ADMIN_ID=envValue('ADMIN_ID','admin').trim();
const ADMIN_PASSWORD=envValue('ADMIN_PASSWORD','');
const SESSION_SECRET=envValue('SESSION_SECRET','');
const EXT_KEY=envValue('EXTENSION_API_KEY','');
if(!ADMIN_PASSWORD||ADMIN_PASSWORD==='GANTI_PASSWORD_KUAT') console.warn('[SECURITY] ADMIN_PASSWORD belum diatur dengan aman.');
if(SESSION_SECRET.length<24) console.warn('[SECURITY] SESSION_SECRET sebaiknya minimal 24 karakter.');
if(EXT_KEY.length<24) console.warn('[SECURITY] EXTENSION_API_KEY sebaiknya minimal 24 karakter.');

const store=new Store(DATA_DIR); const telegram=new Telegram(store);
app.disable('x-powered-by');
app.use(express.json({limit:'18mb'}));
app.use(express.urlencoded({extended:false,limit:'2mb'}));
app.use((req,res,next)=>{
  if(req.path==='/' || req.path==='/index.html' || req.path==='/app.js' || req.path==='/app.css'){
    res.setHeader('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma','no-cache');
    res.setHeader('Expires','0');
  }
  next();
});
app.use((req,res,next)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','same-origin');res.setHeader('X-Frame-Options','DENY');next();});

function b64u(x){return Buffer.from(x).toString('base64url');}
function sign(payload){const p=b64u(JSON.stringify(payload));const s=crypto.createHmac('sha256',SESSION_SECRET||'dev').update(p).digest('base64url');return `${p}.${s}`;}
function verify(tok){try{const [p,s]=tok.split('.');const e=crypto.createHmac('sha256',SESSION_SECRET||'dev').update(p).digest('base64url');if(!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(e)))return null;const v=JSON.parse(Buffer.from(p,'base64url'));if(v.exp<Date.now())return null;return v;}catch{return null;}}
function cookies(req){return Object.fromEntries(String(req.headers.cookie||'').split(';').map(x=>x.trim().split(/=(.*)/s)).filter(x=>x[0]).map(([k,v])=>[k,decodeURIComponent(v||'')]));}
function admin(req,res,next){
  const auth=String(req.get('authorization')||'');
  const bearer=auth.toLowerCase().startsWith('bearer ')?auth.slice(7).trim():'';
  const session=verify(bearer||cookies(req).lc_admin||'');
  if(!session)return res.status(401).json({ok:false,error:'UNAUTHORIZED'});
  req.admin=session;next();
}
function ext(req,res,next){const key=req.get('x-extension-key')||'';if(!EXT_KEY||key.length!==EXT_KEY.length||!crypto.timingSafeEqual(Buffer.from(key),Buffer.from(EXT_KEY)))return res.status(401).json({ok:false,error:'INVALID_EXTENSION_KEY'});res.setHeader('Access-Control-Allow-Origin','*');next();}
app.use('/api/extension',(req,res,next)=>{
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Headers','content-type,x-extension-key');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  if(req.method==='OPTIONS') return res.sendStatus(204);
  next();
});

const loginAttempts=new Map();
function setAdminCookie(req,res,token){
  const secure=req.secure || String(req.get('x-forwarded-proto')||'').split(',')[0].trim()==='https';
  const attrs=[`lc_admin=${encodeURIComponent(token)}`,'Path=/','HttpOnly','SameSite=Lax','Max-Age=43200'];
  if(secure)attrs.push('Secure');
  res.setHeader('Set-Cookie',attrs.join('; '));
}
function clearAdminCookie(req,res){
  const secure=req.secure || String(req.get('x-forwarded-proto')||'').split(',')[0].trim()==='https';
  const attrs=['lc_admin=','Path=/','HttpOnly','SameSite=Lax','Max-Age=0'];
  if(secure)attrs.push('Secure');
  res.setHeader('Set-Cookie',attrs.join('; '));
}
function currentAdmin(req){ return verify(cookies(req).lc_admin||''); }
function adminPage(req,res,next){const session=currentAdmin(req);if(!session)return res.redirect(303,'/');req.admin=session;next();}
function checkLoginAttempt(ip,id,pw){
  const a=loginAttempts.get(ip)||{n:0,until:0};
  if(a.until>Date.now()) return {ok:false,rate:true,error:'Terlalu banyak percobaan. Coba lagi sebentar.'};
  const ok=id===ADMIN_ID && pw===ADMIN_PASSWORD;
  if(!ok){
    a.n++;
    if(a.n>=6){a.until=Date.now()+5*60_000;a.n=0;}
    loginAttempts.set(ip,a);
    store.audit(id||ip,'LOGIN_FAILED');
    return {ok:false,error:'ID atau password salah'};
  }
  loginAttempts.delete(ip);
  return {ok:true};
}
app.get('/',(req,res)=>{
  if(currentAdmin(req))return res.redirect(302,'/dashboard');
  return res.sendFile(path.join(__dirname,'..','public','login.html'));
});
app.get('/dashboard',adminPage,(req,res)=>res.sendFile(path.join(__dirname,'..','public','dashboard.html')));
app.post('/login',(req,res)=>{
  const id=String(req.body.id||'').trim(),pw=String(req.body.password||'');
  const c=checkLoginAttempt(req.ip,id,pw);
  if(!c.ok) return res.redirect(303,`/?login=${c.rate?'rate':'invalid'}`);
  const token=sign({id,exp:Date.now()+12*60*60_000});
  setAdminCookie(req,res,token);store.audit(id,'LOGIN_OK_FORM');
  return res.redirect(303,'/dashboard');
});
app.post('/api/auth/login',(req,res)=>{
  const id=String(req.body.id||'').trim(),pw=String(req.body.password||'');
  const c=checkLoginAttempt(req.ip,id,pw);
  if(!c.ok) return res.status(c.rate?429:401).json({ok:false,error:c.error});
  const token=sign({id,exp:Date.now()+12*60*60_000});
  setAdminCookie(req,res,token);store.audit(id,'LOGIN_OK');res.json({ok:true,id});
});
app.post('/logout',(req,res)=>{clearAdminCookie(req,res);res.redirect(303,'/');});
app.post('/api/auth/logout',(req,res)=>{clearAdminCookie(req,res);res.json({ok:true});});
app.get('/api/auth/me',admin,(req,res)=>res.json({ok:true,id:req.admin.id}));
app.get('/api/health',(req,res)=>res.json({ok:true,service:'livechat-mischat-monitor',version:'1.0.5',admin_id_set:!!ADMIN_ID,admin_password_set:!!ADMIN_PASSWORD,session_secret_set:SESSION_SECRET.length>=24,extension_key_set:EXT_KEY.length>=24,time:new Date().toISOString()}));

app.get('/api/admin/summary',admin,(req,res)=>res.json({ok:true,...store.dashboardSummary()}));
app.get('/api/admin/scans',admin,(req,res)=>res.json({ok:true,items:store.scans(100)}));
app.get('/api/admin/results',admin,(req,res)=>res.json({ok:true,items:store.results(req.query)}));
app.post('/api/admin/scans',admin,(req,res)=>{
  let date=String(req.body.target_date||''); if(!/^\d{4}-\d{2}-\d{2}$/.test(date)){const d=new Date(Date.now()-86400000);date=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Jakarta',year:'numeric',month:'2-digit',day:'2-digit'}).format(d);}
  const out=store.createScan(date,req.admin.id);res.json({ok:true,...out});
});
app.get('/api/admin/settings',admin,(req,res)=>{const s=store.settingsPublic();res.json({ok:true,...s,telegram_token_set:!!store.telegramToken()});});
app.post('/api/admin/settings',admin,(req,res)=>{
  const b=req.body||{}; if('telegram_chat_id'in b)store.settingSet('telegram_chat_id',b.telegram_chat_id);if('telegram_enabled'in b)store.settingSet('telegram_enabled',b.telegram_enabled?'1':'0');if('auto_scan_time'in b)store.settingSet('auto_scan_time',b.auto_scan_time);
  if(String(b.telegram_bot_token||'').trim())store.settingSet('telegram_bot_token',String(b.telegram_bot_token).trim());store.audit(req.admin.id,'SETTINGS_UPDATE');res.json({ok:true,...store.settingsPublic(),telegram_token_set:!!store.telegramToken()});
});
app.post('/api/admin/telegram/test',admin,async(req,res)=>{try{await telegram.sendText(`✅ <b>LiveChat Monitor terhubung</b>\nDashboard dan Telegram berhasil sinkron.`);res.json({ok:true});}catch(e){res.status(400).json({ok:false,error:e.message});}});
app.get('/screenshots/:name',admin,(req,res)=>{const safe=path.basename(req.params.name);const p=path.join(store.shotDir,safe);if(!fs.existsSync(p))return res.sendStatus(404);res.sendFile(p);});

app.post('/api/extension/heartbeat',ext,(req,res)=>{const b=req.body||{}; if(!b.device_id)return res.status(400).json({ok:false,error:'device_id required'});store.upsertDevice({id:b.device_id,name:b.name||b.device_id,version:b.version,error:b.error,currentJob:b.current_job_id});res.json({ok:true,server_time:new Date().toISOString()});});
app.post('/api/extension/jobs/claim',ext,(req,res)=>{const b=req.body||{};if(!b.device_id)return res.status(400).json({ok:false,error:'device_id required'});store.upsertDevice({id:b.device_id,name:b.name||b.device_id,version:b.version});const job=store.claimScan(b.device_id);res.json({ok:true,job});});
app.post('/api/extension/scans/start',ext,(req,res)=>{
  const b=req.body||{};
  if(!b.device_id)return res.status(400).json({ok:false,error:'device_id required'});
  store.upsertDevice({id:b.device_id,name:b.name||b.device_id,version:b.version});
  let date=String(b.target_date||'');
  if(!/^\d{4}-\d{2}-\d{2}$/.test(date)){const d=new Date(Date.now()-86400000);date=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Jakarta',year:'numeric',month:'2-digit',day:'2-digit'}).format(d);}
  const out=store.createScan(date,`extension:${b.device_id}`);
  res.json({ok:true,...out});
});
app.post('/api/extension/jobs/:id/heartbeat',ext,(req,res)=>{const ok=store.heartbeatScan(req.params.id,req.body.device_id,req.body.progress||{});res.status(ok?200:409).json({ok});});
app.post('/api/extension/jobs/:id/results',ext,(req,res)=>{
  const sid=req.params.id,b=req.body||{},s=store.scan(sid); if(!s||s.device_id!==b.device_id||s.status!=='RUNNING')return res.status(409).json({ok:false,error:'JOB_NOT_OWNED'});
  const accepted=[];
  for(const r of (b.items||[]).slice(0,50)){
    if(!r.chat_id||!r.fingerprint||!['NORMAL','MISCHAT','ERROR'].includes(r.status))continue;
    let shot=null; if(r.status==='MISCHAT'&&r.screenshot_data_url){try{shot=store.saveScreenshot(r.chat_id,r.screenshot_data_url);}catch{}}
    const row=store.upsertResult({scan_id:sid,target_date:s.target_date,chat_id:String(r.chat_id),fingerprint:String(r.fingerprint),user_id:String(r.user_id||''),agent:String(r.agent||''),last_customer_text:String(r.last_customer_text||'').slice(0,5000),last_customer_at:String(r.last_customer_at||''),status:r.status,archive_url:String(r.archive_url||''),screenshot_path:shot}); accepted.push(row.id);
  }
  const scan=store.recountScan(sid);res.json({ok:true,accepted,scan});setImmediate(()=>telegram.flush());
});
app.post('/api/extension/jobs/:id/complete',ext,async(req,res)=>{
  const s=store.completeScan(req.params.id,req.body.device_id,Number(req.body.total||0),req.body.error||null);if(!s)return res.status(409).json({ok:false,error:'JOB_NOT_OWNED'});
  res.json({ok:true,scan:s});
  if(s.status==='COMPLETED'&&store.settingsPublic().telegram_enabled){try{await telegram.sendText(`✅ <b>SCAN LIVECHAT SELESAI</b>\nTanggal: <b>${esc(s.target_date)}</b>\nTotal: ${s.total}\nDiperiksa: ${s.checked}\nNormal: ${s.normal}\nMischat: <b>${s.mischat}</b>\nError: ${s.errors}`);}catch(e){console.error('Telegram recap:',e.message);}}
});

app.use(express.static(path.join(__dirname,'..','public'),{index:false,maxAge:0,etag:false}));
app.use((req,res,next)=>{
  if(req.method!=='GET') return next();
  if(req.path.startsWith('/api/') || req.path.startsWith('/screenshots/')) return res.status(404).json({ok:false,error:'NOT_FOUND'});
  return res.redirect(302,currentAdmin(req)?'/dashboard':'/');
});

// Telegram retry queue.
setInterval(()=>telegram.flush().catch(()=>{}),15000).unref();
// Daily auto-job creator, Asia/Jakarta.
let lastAuto='';setInterval(()=>{const cfg=store.settingsPublic();if(!cfg.auto_scan_time)return;const now=new Date();const parts=new Intl.DateTimeFormat('en-GB',{timeZone:'Asia/Jakarta',hour:'2-digit',minute:'2-digit',hourCycle:'h23',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(now);const m=Object.fromEntries(parts.map(p=>[p.type,p.value]));const hhmm=`${m.hour}:${m.minute}`,day=`${m.year}-${m.month}-${m.day}`;if(hhmm===cfg.auto_scan_time&&lastAuto!==day){const y=new Date(now.getTime()-86400000);const target=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Jakarta',year:'numeric',month:'2-digit',day:'2-digit'}).format(y);store.createScan(target,'auto');lastAuto=day;}},30000).unref();

app.listen(PORT,()=>{
  console.log(`LiveChat Mischat Monitor v1.0.5 running on :${PORT}`);
  console.log(`[AUTH] ADMIN_ID=${ADMIN_ID || '(empty)'} | ADMIN_PASSWORD=${ADMIN_PASSWORD?'SET':'EMPTY'} | SESSION_SECRET=${SESSION_SECRET?'SET':'EMPTY'} | EXTENSION_API_KEY=${EXT_KEY?'SET':'EMPTY'}`);
});
