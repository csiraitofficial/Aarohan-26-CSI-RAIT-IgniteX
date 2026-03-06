document.getElementById('readBtn').addEventListener('click', async () => {
  const status = document.getElementById('status');
  const container = document.getElementById('messages');

  container.innerHTML = '';
  status.textContent = 'Reading...';

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab.url.includes('web.whatsapp.com')) {
    status.textContent = '⚠️ Please open WhatsApp Web first.';
    return;
  }

  chrome.tabs.sendMessage(tab.id, { action: 'getMessages' }, (response) => {
    if (chrome.runtime.lastError || !response) {
      status.textContent = '⚠️ Could not read messages. Refresh the page.';
      return;
    }

    const msgs = response.messages;

    if (!msgs.length) {
      status.textContent = 'No messages found. Open a chat first.';
      return;
    }

    status.textContent = `Found ${msgs.length} message(s)`;

    msgs.forEach(m => {
      const div = document.createElement('div');
      div.className = `msg ${m.direction}`;
      div.innerHTML = `<div>${m.text}</div><div class="meta">${m.direction} ${m.time ? '· ' + m.time : ''}</div>`;
      container.appendChild(div);
    });
  });
});
