const $=s=>document.querySelector(s);let state={};
function authToken(){return sessionStorage.getItem('lc_admin_token')||''}
async function api(url,opt={}){const token=authToken();const r=await fetch(url,{...opt,headers:{'content-type':'application/json',...(token?{authorization:`Bearer ${token}`}:{ }),...(opt.headers||{})}});const j=await r.json().catch(()=>({ok:false,error:`HTTP ${r.status}`}));if(r.status===401){showLogin();throw new Error('Unauthorized')}if(!r.ok||!j.ok)throw new Error(j.error||'Request gagal');return j}
function showLogin(){ $('#login').hidden=false;$('#app').hidden=true }
function showApp(){ $('#login').hidden=true;$('#app').hidden=false }
function badge(v){return `<span class="badge ${String(v||'').replace(/[^A-Z_]/g,'')}">${v||'-'}</span>`}
function fmt(s){if(!s)return '-';try{return new Date(s).toLocaleString('id-ID',{timeZone:'Asia/Jakarta'})}catch{return s}}
const loginQuery=new URLSearchParams(location.search).get('login');
if(loginQuery==='invalid') $('#loginErr').textContent='ID atau password salah.';
if(loginQuery==='rate') $('#loginErr').textContent='Terlalu banyak percobaan. Coba lagi sebentar.';
$('#loginForm').onsubmit=async e=>{e.preventDefault();$('#loginErr').textContent='';const btn=$('#loginForm button');btn.disabled=true;try{const r=await fetch('/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id:$('#loginId').value.trim(),password:$('#loginPw').value})});const j=await r.json().catch(()=>({ok:false,error:`HTTP ${r.status}`}));if(!r.ok||!j.ok)throw new Error(j.error||'Login gagal');if(j.token)sessionStorage.setItem('lc_admin_token',j.token);await boot()}catch(err){
  $('#loginErr').textContent=err.message;
  if(/Failed to fetch|NetworkError|Load failed/i.test(String(err.message||''))){
    e.currentTarget.onsubmit=null;
    e.currentTarget.submit();
  }
}finally{btn.disabled=false}}
$('#logoutBtn').onclick=async()=>{sessionStorage.removeItem('lc_admin_token');await fetch('/api/auth/logout',{method:'POST'}).catch(()=>{});showLogin()}
$('#scanBtn').onclick=async()=>{const d=state.yesterday;if(!confirm(`Mulai scan seluruh Archives tanggal ${d} (Yesterday)?`))return;$('#scanBtn').disabled=true;try{await api('/api/admin/scans',{method:'POST',body:JSON.stringify({target_date:d})});await refreshAll()}catch(e){alert(e.message)}finally{$('#scanBtn').disabled=false}}
$('#refreshBtn').onclick=refreshResults;$('#dateFilter').onchange=refreshResults;$('#statusFilter').onchange=refreshResults;
$('#settingsForm').onsubmit=async e=>{e.preventDefault();try{const j=await api('/api/admin/settings',{method:'POST',body:JSON.stringify({telegram_bot_token:$('#tgToken').value,telegram_chat_id:$('#tgChat').value,telegram_enabled:$('#tgEnabled').checked,auto_scan_time:$('#autoTime').value})});$('#tgToken').value='';$('#tgState').textContent=j.telegram_token_set?'Bot token tersimpan':'Bot token belum diatur';alert('Pengaturan tersimpan')}catch(e){alert(e.message)}}
$('#testTg').onclick=async()=>{try{await api('/api/admin/telegram/test',{method:'POST',body:'{}'});alert('Pesan test berhasil dikirim')}catch(e){alert(e.message)}}
async function refreshSummary(){const j=await api('/api/admin/summary');state={...state,...j};const s=j.latest||{};$('#sStatus').innerHTML=badge(s.status||'IDLE');$('#sProgress').textContent=`${s.checked||0} / ${s.total||0}`;$('#sNormal').textContent=s.normal||0;$('#sMischat').textContent=s.mischat||0;$('#sError').textContent=s.errors||0;$('#deviceCount').textContent=`${j.devices.filter(x=>x.online).length} online`;
$('#devices').innerHTML=j.devices.length?j.devices.map(d=>`<div class="device"><div><b>${esc(d.name)}</b><div class="muted">${esc(d.version||'')} ${d.current_job_id?'• '+esc(d.current_job_id):''}</div></div><div class="${d.online?'online':'offline'}">${d.online?'ONLINE':'OFFLINE'}<div class="muted">${fmt(d.last_seen)}</div></div></div>`).join(''):'<div class="muted">Belum ada extension terhubung.</div>';
$('#agents').innerHTML=j.byAgent.length?j.byAgent.map(a=>`<div class="agent-row"><span>${esc(a.agent)}</span><b>${a.count}</b></div>`).join(''):'<div class="muted">Belum ada mischat Yesterday.</div>';if(!$('#dateFilter').value)$('#dateFilter').value=j.yesterday}
async function refreshResults(){const q=new URLSearchParams({date:$('#dateFilter').value||state.yesterday||'',status:$('#statusFilter').value,limit:'500'});const j=await api('/api/admin/results?'+q);$('#results').innerHTML=j.items.length?j.items.map(r=>`<tr><td>${esc(r.last_customer_at||fmt(r.created_at))}</td><td>${esc(r.agent||'-')}</td><td>${esc(r.user_id||'-')}</td><td><a class="link" href="${esc(r.archive_url||'#')}" target="_blank">${esc(r.chat_id)}</a></td><td class="msg">${esc(r.last_customer_text||'-')}</td><td>${badge(r.status)}</td><td>${r.screenshot_path?`<a class="link" href="/screenshots/${encodeURIComponent(r.screenshot_path)}" target="_blank">Screenshot</a>`:'-'}</td><td>${badge(r.telegram_status)}</td></tr>`).join(''):'<tr><td colspan="8" class="muted">Belum ada data.</td></tr>'}
async function refreshScans(){const j=await api('/api/admin/scans');$('#scans').innerHTML=j.items.map(s=>`<tr><td>${s.target_date}</td><td>${badge(s.status)}</td><td>${esc(s.device_id||'-')}</td><td>${s.checked}/${s.total}</td><td>${s.normal}</td><td>${s.mischat}</td><td>${s.errors}</td><td>${fmt(s.started_at)}</td><td>${fmt(s.completed_at)}</td></tr>`).join('')}
async function loadSettings(){const j=await api('/api/admin/settings');$('#tgChat').value=j.telegram_chat_id||'';$('#tgEnabled').checked=!!j.telegram_enabled;$('#autoTime').value=j.auto_scan_time||'';$('#tgState').textContent=j.telegram_token_set?'Bot token sudah tersimpan':'Bot token belum diatur'}
function esc(s=''){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]))}
async function refreshAll(){await Promise.all([refreshSummary(),refreshResults(),refreshScans()])}
async function boot(){try{const me=await api('/api/auth/me');showApp();$('#who').textContent=`Login: ${me.id}`;await refreshSummary();await Promise.all([refreshResults(),refreshScans(),loadSettings()]);setInterval(()=>refreshAll().catch(()=>{}),5000)}catch{showLogin()}}
boot();
