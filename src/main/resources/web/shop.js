const status=document.getElementById('shop-status');let authenticated=false;
async function browse(product){try{const response=await fetch('/api/profile'+(product?'?item='+encodeURIComponent(product):''));if(!response.ok){authenticated=false;status.textContent='Sign in through the security dashboard, then reload this page.';return;}const data=await response.json();authenticated=true;status.textContent='Signed in as '+data.user+' · Connected · Last request '+new Date().toLocaleTimeString();if(product){const panel=document.getElementById('product-detail');panel.hidden=false;panel.textContent=product+' — Item details loaded through the protected website API. Your request is visible in the security dashboard.';}}catch(e){status.textContent='Connection interrupted. Retrying…';}}
for(const button of document.querySelectorAll('[data-product]'))button.onclick=()=>browse(button.dataset.product);
browse();setInterval(()=>{if(authenticated&&!document.hidden)browse();},5000);

const notePanel = document.getElementById('private-note');
const noteText = document.getElementById('note-text');
const noteStatus = document.getElementById('note-status');
let noteCsrf = '';

async function shopApi(path, options) {
    const response = await fetch('/api/' + path, options);
    const data = await response.json();
    if (!response.ok) {
        if (response.status === 401) {
            noteText.value = '';
            notePanel.hidden = true;
            status.textContent = 'Sign in through the security dashboard to access your note.';
        }
        throw new Error(data.error);
    }
    return data;
}

async function openNote() {
    const data = await shopApi('note');
    noteText.value = data.note;
    noteStatus.textContent = data.note ? 'Saved note opened.' : 'You have no saved note yet.';
}

async function updateNote(action) {
    const buttons = notePanel.querySelectorAll('button');
    for (const button of buttons) button.disabled = true;
    try {
        await action();
    } catch (error) {
        noteStatus.textContent = error.message;
    } finally {
        for (const button of buttons) button.disabled = false;
    }
}

document.getElementById('open-note').onclick = () => updateNote(openNote);
document.getElementById('note-form').addEventListener('submit', event => {
    event.preventDefault();
    updateNote(async () => {
        await shopApi('note', {method: 'POST', headers: {'X-CSRF-Token': noteCsrf}, body: noteText.value});
        noteStatus.textContent = 'Note saved.';
    });
});

document.getElementById('shop-logout').onclick = () => updateNote(async () => {
    await shopApi('logout', {method: 'POST', headers: {'X-CSRF-Token': noteCsrf}});
    noteText.value = '';
    notePanel.hidden = true;
    authenticated = false;
    status.textContent = 'Signed out. Sign in again to access your note.';
});

updateNote(async () => {
    const me = await shopApi('me');
    noteCsrf = me.csrf;
    await openNote();
    notePanel.hidden = false;
});
