function getMessages() {
  const messages = [];

  const msgNodes = document.querySelectorAll('div[class*="message-in"], div[class*="message-out"]');

  msgNodes.forEach(node => {
    const textEl = node.querySelector('span.selectable-text');
    const timeEl = node.querySelector('span[data-testid="msg-meta"] span, div[class*="status"] span');
    const isOut = node.className.includes('message-out');

    if (textEl) {
      messages.push({
        text: textEl.innerText,
        time: timeEl ? timeEl.innerText : '',
        direction: isOut ? 'sent' : 'received'
      });
    }
  });

  return messages;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getMessages') {
    sendResponse({ messages: getMessages() });
  }
});
