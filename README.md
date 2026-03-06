# Aarohan-26-CSI-RAIT-IgniteX

# ( will add more content later)

A minimal Chrome extension that reads messages from WhatsApp Web.

## Files

```
wa-reader/
├── manifest.json
├── content.js
├── popup.html
└── popup.js
```

## Install

1. Unzip `wa-reader.zip`
2. Go to `chrome://extensions`
3. Enable **Developer Mode** (top right toggle)
4. Click **Load unpacked** → select the `wa-reader` folder

## Usage

1. Open [web.whatsapp.com](https://web.whatsapp.com)
2. Click into any chat
3. Click the extension icon in the toolbar
4. Click **READ MESSAGES**

Messages are displayed with direction (sent/received) and timestamp.

## Features 

Gmail : by using regex will anylize mail id also if the pattern is not valid of email.id then also it will raise flag fo highlight it 

give toggle to turn on and off extension 
and if user want to turn offf extension for specific site lik whatsapp and telegram also that he will turn off 

machine.
Whats app web 
Telegram 
Email
Outlook 
yahoo mail 
icloud mail 

## How It Works

- `content.js` — injected into WhatsApp Web, queries the DOM for message elements and returns text, time, and direction
- `popup.js` — sends a message to the content script and renders the results in the popup

## Notes

- WhatsApp Web periodically updates its CSS class names. If messages stop showing, the selectors in `content.js` may need updating.
- Only reads messages currently visible in the chat window (no history scrolling).

## Permissions

| Permission | Reason |
|---|---|
| `activeTab` | Read the current tab |
| `scripting` | Inject content script |
| `web.whatsapp.com` | Limit access to WA Web only |
