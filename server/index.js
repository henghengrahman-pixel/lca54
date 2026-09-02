const express=require('express');
const path=require('path');
const fs=require('fs');
const crypto=require('crypto');
const {Store}=require('./store');
const {Telegram,esc}=require('./telegram');

const app=express();
const PORT=Number(process.env.PORT||8080);
const DATA_DIR=process.env.DATA_DIR||path.join(__dirname,'..','data');
const ADMIN_ID=process.env.ADMIN_ID||'admin';
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||'';
const SESSION_SECRET=process.env.SESSION_SECRET||'';
const EXT_KEY=process.env.EXTENSION_API_KEY||'';
if(!ADMIN_PASSWORD||ADMIN_PASSWORD==='GANTI_PASSWORD_KUAT') console.warn('[SECURITY] ADMIN_PASSWORD belum diatur dengan aman.');
if(SESSION_SECRET.length<24) console.warn('[SECURITY] SESSION_SECRET sebaiknya minimal 24 karakter.');
if(EXT_KEY.length<24) console.warn('[SECURITY] EXTENSION_API_KEY sebaiknya minimal 24 karakter.');

const store=new Store(DATA_DIR); const telegram=new Telegram(store);
app.disable('x-powered-by');
app.use(express.json({limit:'18mb'}));
app.use(express.urlencoded({extended:false,limit:'2mb'}));
app.use((req,res,next)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','same-origin');res.setHeader('X-Frame-Options','DENY');next();});

function b64u(x){return Buffer.from(x).toString('base64url');}
function sign(payload){const p=b64u(JSON.stringify(payload));const s=crypto.createHmac('sha256',SESSION_SECRET||'dev').update(p).digest('base64url');return `${p}.${s}`;}
function verify(tok){try{const [p,s]=tok.split('.');const e=crypto.createHmac('sha256',SESSION_SECRET||'dev').update(p).digest('base64url');if(!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(e)))return null;const v=JSON.parse(Buffer.from(p,'base64url'));if(v.exp<Date.now())return null;return v;}catch{return null;}}
function cookies(req){return Object.fromEntries(String(req.headers.cookie||'').split(';').map(x=>x.trim().split(/=(.*)/s)).filter(x=>x[0]).map(([k,v])=>[k,decodeURIComponent(v||'')]));}
function admin(req,res,next){const s=verify(cookies(req).lc_admin||'');if(!s)return res.status(401).json({ok:false,error:'UNAUTHORIZED'});req.admin=s;next();}
function ext(req,res,next){const key=req.get('x-extension-key')||'';if(!EXT_KEY||key.length!==EXT_KEY.length||!crypto.timingSafeEqual(Buffer.from(key),Buffer.from(EXT_KEY)))return res.status(401).json({ok:false,error:'INVALID_EXTENSION_KEY'});res.setHeader('Access-Control-Allow-Origin','*');next();}
app.options('/api/extension/*',(req,res)=>{res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Headers','content-type,x-extension-key');res.sendStatus(204);});

const loginAttempts=new Map();
app.post('/api/auth/login',(req,res)=>{
  const ip=req.ip; const a=loginAttempts.get(ip)||{n:0,until:0}; if(a.until>Date.now())return res.status(429).json({ok:false,error:'Terlalu banyak percobaan. Coba lagi sebentar.'});
  const id=String(req.body.id||''),pw=String(req.body.password||'');
  const ok=id===ADMIN_ID && pw===ADMIN_PASSWORD;
  if(!ok){a.n++;if(a.n>=6){a.until=Date.now()+5*60_000;a.n=0;}loginAttempts.set(ip,a);store.audit(id||ip,'LOGIN_FAILED');return res.status(401).json({ok:false,error:'ID atau password salah'});}
  loginAttempts.delete(ip); const token=sign({id,exp:Date.now()+12*60*60_000});res.setHeader('Set-Cookie',`lc_admin=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200${process.env.NODE_ENV==='production'?'; Secure':''}`);store.audit(id,'LOGIN_OK');res.json({ok:true});
});
app.post('/api/auth/logout',(req,res)=>{res.setHeader('Set-Cookie','lc_admin=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');res.json({ok:true});});
app.get('/api/auth/me',admin,(req,res)=>res.json({ok:true,id:req.admin.id}));

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

app.use(express.static(path.join(__dirname,'..','public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'..','public','index.html')));

// Telegram retry queue.
setInterval(()=>telegram.flush().catch(()=>{}),15000).unref();
// Daily auto-job creator, Asia/Jakarta.
let lastAuto='';setInterval(()=>{const cfg=store.settingsPublic();if(!cfg.auto_scan_time)return;const now=new Date();const parts=new Intl.DateTimeFormat('en-GB',{timeZone:'Asia/Jakarta',hour:'2-digit',minute:'2-digit',hourCycle:'h23',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(now);const m=Object.fromEntries(parts.map(p=>[p.type,p.value]));const hhmm=`${m.hour}:${m.minute}`,day=`${m.year}-${m.month}-${m.day}`;if(hhmm===cfg.auto_scan_time&&lastAuto!==day){const y=new Date(now.getTime()-86400000);const target=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Jakarta',year:'numeric',month:'2-digit',day:'2-digit'}).format(y);store.createScan(target,'auto');lastAuto=day;}},30000).unref();

app.listen(PORT,()=>console.log(`LiveChat Mischat Monitor running on :${PORT}`));
