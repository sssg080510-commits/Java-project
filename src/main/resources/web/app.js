let csrf='', busy=false, currentSessionId='', lookupVersion=0, demoSessionId='';
const $=id=>document.getElementById(id);
function el(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;}
async function api(path,method='GET',body){const r=await fetch('/api/'+path,{method,headers:{'Content-Type':'application/x-www-form-urlencoded','X-CSRF-Token':csrf},body});const data=await r.json();if(!r.ok)throw Error(data.error||'Request failed');return data;}
function message(e){$('message').textContent=e.message||e;}
async function init(){try{const me=await api('me');csrf=me.csrf;currentSessionId=me.sessionId;$('lookup-id').value=currentSessionId;$('lookup-result').textContent='';lookupVersion++;$('auth').hidden=true;$('workspace').hidden=false;$('identity').textContent=(me.admin?'Website monitor · ':'Personal session view · ')+me.user;$('demo').hidden=!(me.admin&&me.lab);$('note-demo').hidden=$('demo').hidden;$('note-demo-result').textContent='';demoSessionId='';$('mode').textContent=(me.lab?'Lab mode: location fixtures are enabled and labelled in the event log. ':'Normal mode: forwarded IP and lab headers are ignored. ')+(me.secureCookie?'Secure cookies enabled.':'Local HTTP: cookie Secure flag is off and will appear as a finding.');await refresh();}catch(e){$('auth').hidden=false;$('workspace').hidden=true;}}
async function refresh(){if(busy||$('workspace').hidden)return;busy=true;try{const d=await api('dashboard');d.sessions.sort((a,b)=>Number(b.id===demoSessionId)-Number(a.id===demoSessionId)||b.score-a.score);$('session-count').textContent=d.sessions.length;$('scenario').textContent=d.scenario;$('connection').textContent='● Live · '+new Date(d.updatedAt).toLocaleTimeString();const threats=d.sessions.filter(s=>s.level==='HIGH');$('threat-banner').classList.toggle('detected',threats.length>0);$('threat-banner').textContent=threats.length?'⚠ SUSPICIOUS SESSION DETECTED — '+threats.map(s=>s.user).join(', ')+' · Review the evidence below.':'Monitoring live traffic · No high-risk session detected';$('event-count').textContent=d.events;$('high-count').textContent=d.sessions.filter(s=>s.level==='HIGH').length;$('session-list').replaceChildren();for(const s of d.sessions){const row=el('article',undefined,'session'),head=el('div',undefined,'session-heading');head.append(el('code',s.user+' · '+s.id.slice(0,12)+'… · '+(s.user.startsWith('lab-note-')?'Synthetic':s.active?'Active':'Ended')),el('span',s.level+' / '+s.score+' points','badge '+s.level));const lookup = el('button', 'Use session ID', 'secondary');
lookup.type = 'button';
lookup.setAttribute('aria-label', 'Use session ID for '+s.user+' · '+s.id.slice(0,12));
lookup.onclick = () => useSessionId(s.id);
head.append(lookup);
row.append(head);if(s.alerts.length){const details=el('details');details.open=s.level==='HIGH';details.append(el('summary',s.alerts.length+' detection signals · View evidence'));for(const a of s.alerts){const p=el('p');p.append(el('b',a.analyzer),el('br'),document.createTextNode(a.explanation),el('br'),document.createTextNode('Suggested response: '+a.recommendation));details.append(p);}row.append(details);}else row.append(el('small','No suspicious signals in the observed window.'));$('session-list').append(row);}$('timeline').replaceChildren();for(const e of d.timeline){const tr=el('tr');for(const t of [e.user,new Date(e.time).toLocaleTimeString(),e.ip,e.path,e.ua,e.simulated?'LAB FIXTURE':'Observed request'])tr.append(el('td',t));$('timeline').append(tr);}}catch(e){$('connection').textContent='○ Connection interrupted';message(e);}finally{busy=false;}}
async function authenticate(register){try{await api(register?'register':'login','POST',new URLSearchParams(new FormData($('auth-form'))));$('auth-form').reset();message('');await init();}catch(e){message(e);}}
$('auth-form').addEventListener('submit',e=>{e.preventDefault();authenticate(false);});$('register').onclick=()=>{if($('auth-form').reportValidity())authenticate(true);};$('demo').onclick=async()=>{try{await api('demo','POST');message('Security test started. Watch the live traffic and alert banner.');await refresh();}catch(e){message(e);}};$('logout').onclick=async()=>{try{await api('logout','POST');csrf='';await init();message('Signed out. Your session has been invalidated.');}catch(e){message(e);}};
function useSessionId(id) {
    lookupVersion++;
    $('lookup-id').value = id;
    $('lookup-result').textContent = '';
    $('lookup-id').focus();
}

$('use-current-session').onclick = () => useSessionId(currentSessionId);
$('lookup-id').addEventListener('input', () => {
    lookupVersion++;
    $('lookup-result').textContent = '';
});

$('session-lookup').addEventListener('submit', async event => {
    event.preventDefault();
    const version = ++lookupVersion;
    const result = $('lookup-result');
    result.textContent = 'Looking up session…';
    try {
        const session = await api('session?id=' + encodeURIComponent($('lookup-id').value));
        if (version !== lookupVersion) return;
        result.textContent = session.user + ' · ' + (session.user.startsWith('lab-note-') ? 'Synthetic' : session.active ? 'Active' : 'Ended')
            + ' · Last seen ' + new Date(session.lastSeen).toLocaleString();
    } catch (error) {
        if (version === lookupVersion) result.textContent = error.message;
    }
});

$('note-demo-form').addEventListener('submit', async event => {
    event.preventDefault();
    const button = event.submitter;
    const result = $('note-demo-result');
    const scenario = $('note-scenario').value;
    button.disabled = true;
    try {
        const demo = await api('note-demo', 'POST', scenario);
        demoSessionId = demo.id;
        const viewer = scenario === 'normal' ? 'Account owner' : 'Simulated intruder';
        result.replaceChildren(
            el('strong', viewer),
            document.createElement('br'),
            document.createTextNode('Test session accepted without a password. Account resolved to ' + demo.user + '.'),
            document.createElement('br'),
            document.createTextNode('Stored private note returned: ' + demo.note)
        );
        await refresh();
    } catch (error) {
        result.textContent = error.message;
    } finally {
        button.disabled = false;
    }
});

init();
setInterval(refresh,1000);
