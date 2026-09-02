const fs=require('fs');
const path=require('path');

function esc(s=''){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
class Telegram {
  constructor(store){this.store=store;this.running=false;}
  cfg(){return {token:this.store.telegramToken(),chatId:this.store.settingsPublic().telegram_chat_id,enabled:this.store.settingsPublic().telegram_enabled};}
  async api(method,body){
    const {token}=this.cfg(); if(!token) throw new Error('TELEGRAM_BOT_TOKEN belum diatur');
    const r=await fetch(`https://api.telegram.org/bot${token}/${method}`,{method:'POST',body});
    const j=await r.json().catch(()=>({ok:false,description:`HTTP ${r.status}`}));
    if(!r.ok||!j.ok) throw new Error(j.description||`Telegram HTTP ${r.status}`); return j;
  }
  caption(row){
    return `⚠️ <b>MISCHAT LIVECHAT</b>\n\n`+
      `<b>Agent:</b> ${esc(row.agent||'-')}\n<b>User ID:</b> ${esc(row.user_id||'-')}\n`+
      `<b>Chat ID:</b> <code>${esc(row.chat_id)}</code>\n<b>Waktu:</b> ${esc(row.last_customer_at||'-')}\n`+
      `<b>Pesan terakhir member:</b> ${esc((row.last_customer_text||'-').slice(0,900))}\n`+
      `<b>Status:</b> TIDAK DIBALAS\n`+
      (row.archive_url?`\n<a href="${esc(row.archive_url)}">Buka Archive</a>`:'');
  }
  async sendResult(row){
    const {chatId,enabled}=this.cfg(); if(!enabled) return {skipped:true}; if(!chatId) throw new Error('TELEGRAM_CHAT_ID belum diatur');
    const caption=this.caption(row);
    if(row.screenshot_path){
      const p=path.join(this.store.shotDir,row.screenshot_path);
      if(fs.existsSync(p)){
        const fd=new FormData(); fd.set('chat_id',chatId); fd.set('parse_mode','HTML'); fd.set('caption',caption.slice(0,1024));
        fd.set('photo',new Blob([fs.readFileSync(p)]),path.basename(p)); return this.api('sendPhoto',fd);
      }
    }
    const fd=new FormData(); fd.set('chat_id',chatId); fd.set('parse_mode','HTML'); fd.set('disable_web_page_preview','true'); fd.set('text',caption.slice(0,4096));
    return this.api('sendMessage',fd);
  }
  async sendText(text){
    const {chatId}=this.cfg(); if(!chatId) throw new Error('TELEGRAM_CHAT_ID belum diatur');
    const fd=new FormData(); fd.set('chat_id',chatId); fd.set('parse_mode','HTML'); fd.set('text',text.slice(0,4096)); return this.api('sendMessage',fd);
  }
  async flush(){
    if(this.running)return; this.running=true;
    try{
      for(const row of this.store.pendingTelegram(10)){
        try{ this.store.setTelegram(row.id,'SENDING'); await this.sendResult(row); this.store.setTelegram(row.id,'SENT'); }
        catch(e){ this.store.setTelegram(row.id,'RETRY',String(e.message||e).slice(0,1000)); }
      }
    }finally{this.running=false;}
  }
}
module.exports={Telegram,esc};
