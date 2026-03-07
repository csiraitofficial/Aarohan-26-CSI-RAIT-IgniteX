(function () {
    'use strict';
    let currentTooltip = null;
    let analysisCache = new Map();
    let pendingAnalysis = new Map();
    let settings = { hoverEnabled: true, blockThreshold: 70 };
    let currentUrl = window.location.href;
    let lastHoveredUrl = null;
    let hoverTimer = null;
    let classifier = null;
    let modelLoading = false;
    let modelReady = false;
    const SUSPICIOUS_TLDS = new Set(['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.click', '.link', '.download', '.win', '.bid', '.stream', '.science', '.racing', '.accountant', '.date', '.faith', '.loan', '.party', '.review', '.trade', '.webcam', '.men', '.gdn', '.kim', '.country', '.cricket', '.work', '.ninja', '.space', '.website', '.site', '.online', '.tech', '.live', '.fun']);
    const SUSPICIOUS_KEYWORDS = ['login', 'signin', 'secure', 'account', 'update', 'verify', 'confirm', 'banking', 'password', 'credential', 'paypal', 'apple', 'amazon', 'google', 'microsoft', 'netflix', 'facebook', 'instagram', 'ebay', 'support', 'helpdesk', 'alert', 'warning', 'suspended', 'locked', 'billing', 'payment', 'invoice', 'refund', 'prize', 'winner', 'congratulation', 'gift', 'free', 'click', 'urgent'];
    const BRAND_DOMAINS = { 'google': ['google.com'], 'facebook': ['facebook.com'], 'microsoft': ['microsoft.com'], 'apple': ['apple.com'], 'amazon': ['amazon.com'], 'paypal': ['paypal.com'], 'netflix': ['netflix.com'] };
    if (typeof window.transformers !== 'undefined') {
        const { env } = window.transformers;
        env.allowLocalModels = false;
        env.useBrowserCache = true;
        env.backends.onnx.wasm.wasmPaths = chrome.runtime.getURL('/');
    }
    async function loadModel() {
        if (classifier || modelLoading) return;
        modelLoading = true;
        try {
            const { pipeline } = window.transformers;
            const modelUrl = chrome.runtime.getURL('models/Xenova/distilbert-base-uncased-finetuned-sst-2-english/');
            classifier = await pipeline('text-classification', modelUrl, { quantized: true });
            modelReady = true;
            console.log('[AegisAI] Link Hover Neural Model Ready');
        } catch (e) {
            console.error('[AegisAI] Model Load Failed:', e);
        } finally {
            modelLoading = false;
        }
    }
    async function explainUrl(url, hostname, baseScore) {
        if (!classifier || baseScore < 0.3) return [];
        const phrases = hostname.split(/[.\/-]/).filter(p => p.length > 2);
        const shapValues = [];
        for (const phrase of phrases) {
            const maskedHostname = hostname.replace(phrase, "mask");
            const maskedUrl = url.replace(hostname, maskedHostname);
            try {
                const res = await classifier(`URL: ${maskedUrl}. Domain: ${maskedHostname}.`);
                if (res && res[0]) {
                    const maskedScore = res[0].score;
                    const contribution = baseScore - maskedScore;
                    if (contribution > 0.1) {
                        shapValues.push({
                            phrase,
                            impact: Math.round(contribution * 100),
                            explanation: getHumanExplanation(phrase)
                        });
                    }
                }
            } catch (e) { }
        }
        return shapValues.sort((a, b) => b.impact - a.impact).slice(0, 2);
    }
    function getHumanExplanation(phrase) {
        if (/(login|signin|secure|account|verify)/i.test(phrase)) return "This word is a 'security hook' used to create trust.";
        if (/(urgent|action|expire|prize|offer)/i.test(phrase)) return "Creates artificial urgency to make you click without thinking.";
        if (/(update|payment|bill|card|bank)/i.test(phrase)) return "Targets sensitive financial and credential information.";
        return "The AI identifies this term as a common phishing indicator.";
    }
    const INSTANT_PATTERNS = [
        { pattern: /(\d{1,3}\.){3}\d{1,3}/, reason: 'Uses a numeric address instead of a name. Legitimate sites use names like "google.com".', weight: 30 },
        { pattern: /https?:\/\/[^/]*@/, reason: 'URL contains a "hidden redirect" symbol (@).', weight: 25 },
        { pattern: /(login|signin|secure|verify|confirm|update|account|password|banking).*\.(xyz|tk|ml|ga|cf|gq|pw|top|click|download|win|bid|stream)/, reason: 'Sensitive keyword with a suspicious web ending.', weight: 45 },
        { pattern: /([a-z0-9-]+\.){4,}[a-z]+/, reason: 'The address is buried under too many sections (subdomains).', weight: 20 },
        { pattern: /%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}/, reason: 'Uses encoded characters to hide the destination.', weight: 15 },
        { pattern: /\.(exe|php|asp|zip|rar|cmd|bat|vbs|ps1|jar)(\?|$|#)/, reason: 'Leads to a dangerous file type.', weight: 20 },
        { pattern: /(paypa[^.]*\.|micros[0o]ft[^.]*\.|g[o0]{2}gle[^.]*\.|faceb[o0]{2}k[^.]*\.|amaz[o0]n[^.]*\.)/, reason: 'Slightly misspelled to impersonate a brand.', weight: 38 },
        { pattern: /\/\/{2,}/, reason: 'Unusual double slashes found.', weight: 12 },
        { pattern: /[а-яА-Я]/, reason: 'Uses lookalike "homograph" characters to trick you.', weight: 35 },
    ];
    function quickRegexCheck(url) {
        const hits = [];
        for (const { pattern, reason, weight } of INSTANT_PATTERNS) {
            if (pattern.test(url)) hits.push({ reason, weight });
        }
        return hits;
    }
    function buildTooltipHTML(result, isLoading) {
        if (isLoading) {
            return `
                <div class="aegis-tooltip-wrap">
                    <div class="aegis-header">
                        <div class="aegis-logo">🛡️ AegisAI</div>
                        <div class="aegis-scanning">Analyzing…</div>
                    </div>
                    <div class="aegis-loading-bar"><div class="aegis-loading-bar-inner"></div></div>
                </div>
            `;
        }
        const { score, level, label, flags, hostname, isHttps, url } = result;
        const levelColors = { safe: '#22c55e', low: '#84cc16', medium: '#f59e0b', high: '#ef4444', critical: '#a855f7' };
        const color = levelColors[level] || '#6b7280';
        let flagsHTML = (flags.length > 0)
            ? flags.map(f => `
                <div class="aegis-flag aegis-flag-${level}">
                    <span class="aegis-flag-icon">${getFlagIcon(f.type)}</span>
                    <div class="aegis-flag-content"><span class="aegis-flag-text">${f.text}</span></div>
                </div>`).join('')
            : `<div class="aegis-flag aegis-flag-safe"><span class="aegis-flag-icon">✅</span><span>No obvious threats detected.</span></div>`;
        if (result.shap && result.shap.length > 0) {
            const bubbel = result.shap[0];
            flagsHTML = `
                <div class="aegis-flag aegis-flag-critical" style="border-left: 3px solid #ef4444; background: rgba(239,68,68,0.05); padding: 10px; border-radius: 8px; margin-bottom: 10px;">
                    <div style="font-size: 10px; color: #ef4444; font-weight: 800; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px;">🧠 Flagged Phrase</div>
                    <div style="font-size: 12px; color: #f8fafc; font-weight: 700; font-family: monospace; margin-bottom: 4px;">"${bubbel.phrase}"</div>
                    <div style="font-size: 11px; color: #94a3b8; line-height: 1.4;">${bubbel.explanation}</div>
                </div>` + flagsHTML;
        }
        return `
            <div class="aegis-tooltip-wrap aegis-${level}">
                <div class="aegis-header">
                    <div class="aegis-logo">🛡️ AegisAI <span style="font-size: 8px; font-weight: 400; color: #94a3b8; background: rgba(255,255,255,0.05); padding: 2px 4px; border-radius: 4px; margin-left: 4px;">LOCAL AI</span></div>
                    <button class="aegis-close-btn" id="aegis-close">✕</button>
                </div>
                <div class="aegis-score-row">
                    <svg class="aegis-ring" viewBox="0 0 36 36" width="64" height="64">
                        <circle cx="18" cy="18" r="15.9" fill="none" stroke="#1e293b" stroke-width="3"/>
                        <circle cx="18" cy="18" r="15.9" fill="none" stroke="${color}" stroke-width="3" stroke-dasharray="${score} ${100 - score}" stroke-dashoffset="25" stroke-linecap="round" transform="rotate(-90 18 18)"/>
                        <text x="18" y="18" text-anchor="middle" dominant-baseline="middle" fill="${color}" font-size="8" font-weight="bold">${score}</text>
                    </svg>
                    <div class="aegis-score-info">
                        <div class="aegis-label" style="color:${color}">${label}</div>
                        <div class="aegis-hostname">${hostname}</div>
                        <div class="aegis-https ${isHttps ? 'aegis-https-ok' : 'aegis-https-bad'}">${isHttps ? '🔒 HTTPS' : '⚠️ NOT HTTPS'}</div>
                        ${result.domainAge !== null && result.domainAge !== undefined
                ? `<div style="margin-top:4px;font-size:9px;padding:2px 6px;border-radius:4px;display:inline-flex;align-items:center;gap:4px;border:1px solid ${result.domainAge < 30 ? 'rgba(239,68,68,0.4)' : result.domainAge < 180 ? 'rgba(245,158,11,0.4)' : 'rgba(34,197,94,0.3)'};background:${result.domainAge < 30 ? 'rgba(239,68,68,0.1)' : result.domainAge < 180 ? 'rgba(245,158,11,0.08)' : 'rgba(34,197,94,0.05)'};color:${result.domainAge < 30 ? '#ef4444' : result.domainAge < 180 ? '#f59e0b' : '#22c55e'};font-weight:700;">
                              ${result.domainAge < 30 ? '🆕' : result.domainAge < 180 ? '📅' : '✅'}
                              ${result.domainAge < 1 ? 'Brand new today' : result.domainAge < 30 ? `${result.domainAge}d old — Very New!` : result.domainAge < 180 ? `${result.domainAge}d old — Recent` : `${Math.floor(result.domainAge / 365)}yr ${Math.floor((result.domainAge % 365) / 30)}mo old`}
                            </div>`
                : result.domainAgeFailed
                    ? `<div style="margin-top:4px;font-size:9px;padding:2px 6px;border-radius:4px;display:inline-flex;align-items:center;gap:4px;border:1px solid rgba(148,163,184,0.3);background:rgba(148,163,184,0.05);color:#94a3b8;font-weight:700;">
                                  ❓ Age data unavailable
                               </div>`
                    : `<div style="margin-top:4px;font-size:9px;padding:2px 6px;border-radius:4px;display:inline-flex;align-items:center;gap:4px;border:1px solid rgba(56,189,248,0.3);background:rgba(56,189,248,0.05);color:#38bdf8;font-weight:700;">
                                  🛡️ Checking domain age...
                               </div>`}
                    </div>
                </div>
                <div class="aegis-divider"></div>
                <div class="aegis-flags-list">${flagsHTML}</div>
                ${score >= 45 ? `<div class="aegis-actions">
                    <button class="aegis-btn aegis-btn-block" id="aegis-block-btn" data-hostname="${hostname}">🚫 Block</button>
                    <button class="aegis-btn aegis-btn-proceed" id="aegis-proceed-btn" data-url="${encodeURIComponent(url)}">⚡ Proceed</button>
                </div>` : ''}
            </div>
        `;
    }
    function getFlagIcon(type) {
        const icons = { suspicious_tld: '🔴', ip_address: '🌐', many_subdomains: '📛', suspicious_keywords: '🔑', long_url: '📏', at_sign: '⚠️', double_slash: '⚡', many_dots: '⠿', no_https: '🔓', special_chars: '💉', homograph: '🎭', brand_impersonation: '🎭', typosquatting: '🔢', high_entropy: '🌀', many_dashes: '—', encoded_chars: '🔏', suspicious_extension: '📁', long_query: '📋', https_subdomain: '🛡️', brand_in_path: '🗺️', blocklist: '🚫', ai_model: '🧠', new_domain: '🆕', recent_domain: '📅' };
        return icons[type] || '⚠️';
    }
    function createTooltip(x, y, htmlContent) {
        removeTooltip();
        const div = document.createElement('div');
        div.id = 'aegis-tooltip';
        div.innerHTML = htmlContent;
        document.body.appendChild(div);
        positionTooltip(div, x, y);
        currentTooltip = div;
        wireButtons(div);
        return div;
    }
    function wireButtons(el) {
        el.querySelector('#aegis-close')?.addEventListener('click', removeTooltip);
        el.querySelector('#aegis-block-btn')?.addEventListener('click', (e) => {
            const h = e.target.dataset.hostname;
            chrome.runtime.sendMessage({ type: 'ADD_TO_BLOCKLIST', hostname: h });
            showNotification(`🚫 ${h} blocked`, 'danger');
            removeTooltip();
        });
        el.querySelector('#aegis-proceed-btn')?.addEventListener('click', (e) => {
            window.open(decodeURIComponent(e.target.dataset.url), '_blank');
            removeTooltip();
        });
    }
    function positionTooltip(el, x, y) {
        const w = Math.min(380, window.innerWidth - 32);
        el.style.width = w + 'px';
        let left = x + 16, top = y + 16;
        if (left + w > window.innerWidth - 16) left = x - w - 8;
        if (top + 320 > window.innerHeight) top = y - 320;
        el.style.left = Math.max(8, left) + 'px';
        el.style.top = Math.max(8, top) + 'px';
    }
    function removeTooltip() {
        if (currentTooltip) { currentTooltip.remove(); currentTooltip = null; }
    }
    function showNotification(msg, type = 'info') {
        const el = document.createElement('div');
        el.className = `aegis-notif aegis-notif-${type}`;
        el.textContent = msg;
        document.body.appendChild(el);
        setTimeout(() => el.classList.add('aegis-notif-show'), 10);
        setTimeout(() => { el.classList.remove('aegis-notif-show'); setTimeout(() => el.remove(), 400); }, 3500);
    }
    function getHoveredLink(e) {
        let el = e.target;
        while (el && el !== document.body) { if (el.tagName === 'A' && el.href && el.href.startsWith('http')) return el; el = el.parentElement; }
        return null;
    }
    document.addEventListener('mouseover', (e) => {
        if (!settings.hoverEnabled) return;
        const link = getHoveredLink(e);
        if (!link) return;
        if (link.href === lastHoveredUrl && currentTooltip) return;
        lastHoveredUrl = link.href;
        clearTimeout(hoverTimer);
        hoverTimer = setTimeout(() => {
            loadModel();
            showAnalysis(link.href, e.clientX + window.scrollX, e.clientY + window.scrollY);
        }, 50);
    });
    document.addEventListener('mouseout', (e) => {
        if (!getHoveredLink(e)) {
            clearTimeout(hoverTimer);
            setTimeout(() => { if (currentTooltip && !currentTooltip.matches(':hover')) removeTooltip(); }, 1500);
        }
    });
    async function showAnalysis(url, x, y) {
        if (analysisCache.has(url)) { createTooltip(x, y, buildTooltipHTML(analysisCache.get(url), false)); return; }
        createTooltip(x, y, buildTooltipHTML(null, true));
        const quickHits = quickRegexCheck(url);
        if (quickHits.length > 0 && quickHits.reduce((s, h) => s + h.weight, 0) >= settings.blockThreshold) showNotification('⚠️ Suspicious link detected!', 'warning');
        if (modelReady) {
            try {
                const parsed = new URL(url);
                const res = await classifier(`URL: ${url}. Domain: ${parsed.hostname}.`);
                if (res && res[0]) {
                    const prob = res[0].score;
                    const level = prob > 0.7 ? 'critical' : (prob > 0.4 ? 'high' : 'low');
                    const localResult = {
                        url, hostname: parsed.hostname, score: Math.round(prob * 100), level, label: level.toUpperCase(),
                        flags: quickHits.map(h => ({ type: 'ai_model', text: h.reason })), isHttps: url.startsWith('https'),
                        shap: await explainUrl(url, parsed.hostname, prob)
                    };
                    if (currentTooltip && lastHoveredUrl === url) { currentTooltip.innerHTML = buildTooltipHTML(localResult, false); wireButtons(currentTooltip); }
                    analysisCache.set(url, localResult);
                    chrome.runtime.sendMessage({ type: 'GET_DOMAIN_AGE', hostname: parsed.hostname }, (ageResult) => {
                        if (!chrome.runtime.lastError && ageResult) {
                            localResult.domainAge = ageResult.ageInDays;
                            localResult.firstCertDate = ageResult.firstCertDate;
                            localResult.domainAgeFailed = (ageResult.ageInDays === null);
                            analysisCache.set(url, localResult);
                            if (currentTooltip && lastHoveredUrl === url) {
                                currentTooltip.innerHTML = buildTooltipHTML(localResult, false);
                                wireButtons(currentTooltip);
                            }
                        }
                    });
                    return;
                }
            } catch (e) { }
        }
        chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url }, (result) => {
            if (!chrome.runtime.lastError && result) {
                if (result.domainAge === null || result.domainAge === undefined) {
                    result.domainAgeFailed = true;
                }
                analysisCache.set(url, result);
                if (currentTooltip && lastHoveredUrl === url) { currentTooltip.innerHTML = buildTooltipHTML(result, false); wireButtons(currentTooltip); }
            }
        });
    }
    function analyzeCurrentPage() {
        chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url: window.location.href }, (result) => {
            if (!chrome.runtime.lastError && result && result.score >= 45) injectAmbientRisk(result);
        });
    }
    function injectAmbientRisk(result) {
        document.getElementById('aegis-ambient')?.remove();
        const color = { medium: '#f59e0b', high: '#ef4444', critical: '#a855f7' }[result.level] || '#ef4444';
        const div = document.createElement('div');
        div.id = 'aegis-ambient';
        div.style.cssText = `position:fixed;top:0;left:0;right:0;bottom:0;pointer-events:none;z-index:2147483640;box-shadow:inset 0 0 60px 20px ${color}44;border:2px solid ${color}66;animation:aegis-pulse 2s ease-in-out infinite;`;
        document.body.appendChild(div);
    }
    document.addEventListener('click', (e) => {
        const link = getHoveredLink(e);
        if (!link) return;
        const cached = analysisCache.get(link.href);
        if (cached && cached.score >= (settings.blockThreshold || 70)) {
            e.preventDefault();
            window.location.href = chrome.runtime.getURL(`blocked.html?data=${encodeURIComponent(JSON.stringify(cached))}`);
        }
    }, true);
    chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, (s) => { if (s) settings = { ...settings, ...s }; });
    analyzeCurrentPage();
    console.log('[AegisAI] Active');
})();