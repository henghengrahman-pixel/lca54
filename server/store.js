const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

function nowIso(){ return new Date().toISOString(); }
function id(prefix='id'){ return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2,10)}`; }

class Store {
  constructor(dataDir){
    fs.mkdirSync(dataDir, {recursive:true});
    this.dataDir = dataDir;
    this.shotDir = path.join(dataDir, 'screenshots');
    fs.mkdirSync(this.shotDir, {recursive:true});
    this.db = new Database(path.join(dataDir, 'monitor.db'));
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.migrate();
  }
  migrate(){
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL, updated_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, version TEXT, online INTEGER NOT NULL DEFAULT 0,
        last_seen TEXT, last_error TEXT, current_job_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY, target_date TEXT NOT NULL, status TEXT NOT NULL, device_id TEXT,
        total INTEGER NOT NULL DEFAULT 0, checked INTEGER NOT NULL DEFAULT 0, normal INTEGER NOT NULL DEFAULT 0,
        mischat INTEGER NOT NULL DEFAULT 0, errors INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL, started_at TEXT, completed_at TEXT, lock_until TEXT, error TEXT
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_active_date ON scans(target_date, status) WHERE status IN ('QUEUED','RUNNING');
      CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, target_date TEXT NOT NULL,
        chat_id TEXT NOT NULL, fingerprint TEXT NOT NULL, user_id TEXT, agent TEXT,
        last_customer_text TEXT, last_customer_at TEXT, status TEXT NOT NULL,
        archive_url TEXT, screenshot_path TEXT, telegram_status TEXT NOT NULL DEFAULT 'NOT_SENT',
        telegram_error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        UNIQUE(target_date, chat_id, fingerprint)
      );
      CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id);
      CREATE INDEX IF NOT EXISTS idx_results_status ON results(target_date,status);
      CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT
      );
    `);
  }
  audit(actor, action, detail=''){
    this.db.prepare('INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)').run(nowIso(), actor, action, String(detail||'').slice(0,4000));
  }
  settingGet(k){ const r=this.db.prepare('SELECT v FROM settings WHERE k=?').get(k); return r?.v ?? null; }
  settingSet(k,v){ this.db.prepare(`INSERT INTO settings(k,v,updated_at) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v,updated_at=excluded.updated_at`).run(k,String(v??''),nowIso()); }
  settingsPublic(){
    return {
      telegram_chat_id: this.settingGet('telegram_chat_id') || process.env.TELEGRAM_CHAT_ID || '',
      telegram_enabled: (this.settingGet('telegram_enabled') ?? '1') === '1',
      auto_scan_time: this.settingGet('auto_scan_time') || process.env.AUTO_SCAN_TIME || '',
    };
  }
  telegramToken(){ return this.settingGet('telegram_bot_token') || process.env.TELEGRAM_BOT_TOKEN || ''; }
  upsertDevice({id:deviceId,name,version,error,currentJob}){
    const n=nowIso();
    this.db.prepare(`INSERT INTO devices(id,name,version,online,last_seen,last_error,current_job_id,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,version=excluded.version,online=1,last_seen=excluded.last_seen,last_error=excluded.last_error,current_job_id=excluded.current_job_id,updated_at=excluded.updated_at`)
      .run(deviceId,name||deviceId,version||'',1,n,error||null,currentJob||null,n,n);
  }
  markOfflineStale(seconds=45){
    const cutoff=new Date(Date.now()-seconds*1000).toISOString();
    this.db.prepare('UPDATE devices SET online=0 WHERE last_seen < ?').run(cutoff);
  }
  devices(){ this.markOfflineStale(); return this.db.prepare('SELECT * FROM devices ORDER BY online DESC,last_seen DESC').all(); }
  createScan(targetDate, actor='admin'){
    const existing=this.db.prepare("SELECT * FROM scans WHERE target_date=? AND status IN ('QUEUED','RUNNING') ORDER BY created_at DESC LIMIT 1").get(targetDate);
    if(existing) return {scan:existing, existed:true};
    const sid=id('scan'), n=nowIso();
    this.db.prepare(`INSERT INTO scans(id,target_date,status,created_at) VALUES(?,?,?,?)`).run(sid,targetDate,'QUEUED',n);
    this.audit(actor,'SCAN_CREATED',`${sid} ${targetDate}`);
    return {scan:this.scan(sid), existed:false};
  }
  scan(sid){ return this.db.prepare('SELECT * FROM scans WHERE id=?').get(sid); }
  scans(limit=50){ return this.db.prepare('SELECT * FROM scans ORDER BY created_at DESC LIMIT ?').all(limit); }
  claimScan(deviceId){
    const tx=this.db.transaction(()=>{
      const n=nowIso();
      // Recover expired locks.
      this.db.prepare("UPDATE scans SET status='QUEUED',device_id=NULL,lock_until=NULL,error=COALESCE(error,'') WHERE status='RUNNING' AND lock_until IS NOT NULL AND lock_until < ?").run(n);
      const s=this.db.prepare("SELECT * FROM scans WHERE status='QUEUED' ORDER BY created_at ASC LIMIT 1").get();
      if(!s) return null;
      const lockUntil=new Date(Date.now()+60_000).toISOString();
      this.db.prepare("UPDATE scans SET status='RUNNING',device_id=?,started_at=COALESCE(started_at,?),lock_until=? WHERE id=?").run(deviceId,n,lockUntil,s.id);
      return this.scan(s.id);
    });
    return tx();
  }
  heartbeatScan(sid,deviceId,progress={}){
    const s=this.scan(sid); if(!s || s.device_id!==deviceId || s.status!=='RUNNING') return false;
    const lockUntil=new Date(Date.now()+60_000).toISOString();
    this.db.prepare(`UPDATE scans SET lock_until=?,total=MAX(total,?),checked=MAX(checked,?),normal=MAX(normal,?),mischat=MAX(mischat,?),errors=MAX(errors,?) WHERE id=?`)
      .run(lockUntil,progress.total||0,progress.checked||0,progress.normal||0,progress.mischat||0,progress.errors||0,sid);
    return true;
  }
  upsertResult(r){
    const n=nowIso();
    const info=this.db.prepare(`INSERT INTO results(scan_id,target_date,chat_id,fingerprint,user_id,agent,last_customer_text,last_customer_at,status,archive_url,screenshot_path,created_at,updated_at)
      VALUES(@scan_id,@target_date,@chat_id,@fingerprint,@user_id,@agent,@last_customer_text,@last_customer_at,@status,@archive_url,@screenshot_path,@created_at,@updated_at)
      ON CONFLICT(target_date,chat_id,fingerprint) DO UPDATE SET scan_id=excluded.scan_id,user_id=excluded.user_id,agent=excluded.agent,last_customer_text=excluded.last_customer_text,last_customer_at=excluded.last_customer_at,status=excluded.status,archive_url=excluded.archive_url,screenshot_path=COALESCE(excluded.screenshot_path,results.screenshot_path),updated_at=excluded.updated_at`)
      .run({...r,created_at:n,updated_at:n});
    return this.db.prepare('SELECT * FROM results WHERE target_date=? AND chat_id=? AND fingerprint=?').get(r.target_date,r.chat_id,r.fingerprint);
  }
  saveScreenshot(chatId, dataUrl){
    if(!dataUrl) return null;
    const m=/^data:image\/(png|jpeg);base64,(.+)$/s.exec(dataUrl); if(!m) return null;
    const ext=m[1]==='jpeg'?'jpg':'png';
    const safe=String(chatId).replace(/[^a-zA-Z0-9_-]/g,'_');
    const name=`${Date.now()}-${safe}.${ext}`;
    fs.writeFileSync(path.join(this.shotDir,name),Buffer.from(m[2],'base64'));
    return name;
  }
  resultById(id){ return this.db.prepare('SELECT * FROM results WHERE id=?').get(id); }
  results(filters={}){
    const where=[],args=[];
    if(filters.date){ where.push('target_date=?'); args.push(filters.date); }
    if(filters.status){ where.push('status=?'); args.push(filters.status); }
    if(filters.agent){ where.push('agent=?'); args.push(filters.agent); }
    const lim=Math.min(Number(filters.limit)||200,1000);
    return this.db.prepare(`SELECT * FROM results ${where.length?'WHERE '+where.join(' AND '):''} ORDER BY created_at DESC LIMIT ?`).all(...args,lim);
  }
  recountScan(sid){
    const rows=this.db.prepare(`SELECT status,COUNT(*) c FROM results WHERE scan_id=? GROUP BY status`).all(sid);
    const counts={NORMAL:0,MISCHAT:0,ERROR:0}; rows.forEach(r=>counts[r.status]=r.c);
    const checked=rows.reduce((a,r)=>a+r.c,0);
    this.db.prepare('UPDATE scans SET checked=?,normal=?,mischat=?,errors=? WHERE id=?').run(checked,counts.NORMAL||0,counts.MISCHAT||0,counts.ERROR||0,sid);
    return this.scan(sid);
  }
  completeScan(sid,deviceId,total,error=null){
    const s=this.scan(sid); if(!s || s.device_id!==deviceId) return null;
    const status=error?'FAILED':'COMPLETED';
    this.db.prepare('UPDATE scans SET status=?,total=MAX(total,?),completed_at=?,lock_until=NULL,error=? WHERE id=?').run(status,total||0,nowIso(),error||null,sid);
    return this.recountScan(sid);
  }
  pendingTelegram(limit=20){ return this.db.prepare("SELECT * FROM results WHERE status='MISCHAT' AND telegram_status IN ('NOT_SENT','RETRY') ORDER BY created_at ASC LIMIT ?").all(limit); }
  setTelegram(id,status,error=null){ this.db.prepare('UPDATE results SET telegram_status=?,telegram_error=?,updated_at=? WHERE id=?').run(status,error,nowIso(),id); }
  dashboardSummary(){
    this.markOfflineStale();
    const today=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Jakarta',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());
    const y=new Date(Date.now()-86400000); const yesterday=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Jakarta',year:'numeric',month:'2-digit',day:'2-digit'}).format(y);
    const latest=this.db.prepare('SELECT * FROM scans ORDER BY created_at DESC LIMIT 1').get()||null;
    const byAgent=this.db.prepare("SELECT COALESCE(agent,'Unknown') agent,COUNT(*) count FROM results WHERE target_date=? AND status='MISCHAT' GROUP BY agent ORDER BY count DESC").all(yesterday);
    return {today,yesterday,latest,devices:this.devices(),byAgent};
  }
}
module.exports={Store};
