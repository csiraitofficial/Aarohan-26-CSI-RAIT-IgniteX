
// ============================================================
// AegisAI Content Script v2.0
// Hover over any link → instant phishing analysis + XAI panel
// Regex-based blocking happens BEFORE page loads (via background)
// ============================================================

(function () {
    'use strict';

    // ---------- State ----------
    let currentTooltip = null;
    let analysisCache = new Map();
    let pendingAnalysis = new Map();
    let settings = { hoverEnabled: true, blockThreshold: 70 };
    let currentUrl = window.location.href;
    let selfBlocked = false;

    // ---------- Regex Patterns for Instant Detection ----------
    const INSTANT_PATTERNS = [
        { pattern: /(\d{1,3}\.){3}\d{1,3}/, reason: 'IP address used as domain', weight: 30 },
        { pattern: /https?:\/\/[^/]*@/, reason: 'URL contains "@" redirect trick', weight: 25 },
        { pattern: /(login|signin|secure|verify|confirm|update|account|password|banking).*\.(xyz|tk|ml|ga|cf|gq|pw|top|click|download|win|bid|stream)/, reason: 'Phishing keyword + suspicious TLD', weight: 45 },
        { pattern: /([a-z0-9-]+\.){4,}[a-z]+/, reason: 'Excessive subdomain nesting', weight: 20 },
        { pattern: /%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}/, reason: 'Multiple URL-encoded characters (obfuscation)', weight: 15 },
        { pattern: /\.(exe|php|asp|zip|rar|cmd|bat|vbs|ps1|jar)(\?|$|#)/, reason: 'Dangerous file type in URL', weight: 20 },
        { pattern: /(paypa[^.]*\.|micros[0o]ft[^.]*\.|g[o0]{2}gle[^.]*\.|faceb[o0]{2}k[^.]*\.|amaz[o0]n[^.]*\.)/, reason: 'Typosquatting a known brand', weight: 38 },
        { pattern: /\/\/{2,}/, reason: 'Double slashes in path (obfuscation)', weight: 12 },
        { pattern: /[а-яА-Я]/, reason: 'Cyrillic characters in URL (homograph attack)', weight: 35 },
    ];

    function quickRegexCheck(url) {
        const hits = [];
        for (const { pattern, reason, weight } of INSTANT_PATTERNS) {
            if (pattern.test(url)) hits.push({ reason, weight });
        }
        return hits;
    }

    // ---------- Tooltip HTML Builder ----------
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

        const flagsHTML = flags.length > 0
            ? flags.map(f => `
          <div class="aegis-flag aegis-flag-${level}">
            <span class="aegis-flag-icon">${getFlagIcon(f.type)}</span>
            <span>${f.text}</span>
          </div>`).join('')
            : `<div class="aegis-flag aegis-flag-safe"><span class="aegis-flag-icon">✅</span><span>No phishing indicators detected</span></div>`;

        const scoreRing = `
      <svg class="aegis-ring" viewBox="0 0 36 36" width="64" height="64">
        <circle cx="18" cy="18" r="15.9" fill="none" stroke="#1e293b" stroke-width="3"/>
        <circle cx="18" cy="18" r="15.9" fill="none" stroke="${color}" stroke-width="3"
          stroke-dasharray="${score} ${100 - score}" stroke-dashoffset="25"
          stroke-linecap="round" transform="rotate(-90 18 18)"/>
        <text x="18" y="18" text-anchor="middle" dominant-baseline="middle"
          fill="${color}" font-size="8" font-weight="bold" font-family="Inter,sans-serif">${score}</text>
      </svg>
    `;

        return `
      <div class="aegis-tooltip-wrap aegis-${level}">
        <div class="aegis-header">
          <div class="aegis-logo">🛡️ AegisAI</div>
          <button class="aegis-close-btn" id="aegis-close">✕</button>
        </div>
        <div class="aegis-score-row">
          ${scoreRing}
          <div class="aegis-score-info">
            <div class="aegis-label" style="color:${color}">${label}</div>
            <div class="aegis-hostname">${hostname}</div>
            <div class="aegis-https ${isHttps ? 'aegis-https-ok' : 'aegis-https-bad'}">${isHttps ? '🔒 HTTPS' : '⚠️ NOT HTTPS'}</div>
          </div>
        </div>
        <div class="aegis-divider"></div>
        <div class="aegis-xai-title">🔍 Why? Explainable AI Analysis</div>
        <div class="aegis-flags-list">${flagsHTML}</div>
        ${flags.length === 0 ? '' : `
        <div class="aegis-divider"></div>
        <div class="aegis-xai-edu">
          <span>💡</span>
          <span>${getEducationalTip(level, flags)}</span>
        </div>`}
        ${score >= 45 ? `
        <div class="aegis-actions">
          <button class="aegis-btn aegis-btn-block" id="aegis-block-btn" data-hostname="${hostname}">🚫 Block This Site</button>
          <button class="aegis-btn aegis-btn-proceed" id="aegis-proceed-btn" data-url="${encodeURIComponent(url)}">⚡ Proceed Anyway</button>
        </div>` : ''}
      </div>
    `;
    }

    function getFlagIcon(type) {
        const icons = {
            suspicious_tld: '🔴', ip_address: '🌐', many_subdomains: '📛',
            suspicious_keywords: '🔑', long_url: '📏', at_sign: '⚠️',
            double_slash: '⚡', many_dots: '⠿', no_https: '🔓',
            special_chars: '💉', homograph: '🎭', brand_impersonation: '🎭',
            typosquatting: '🔢', high_entropy: '🌀', many_dashes: '—',
            encoded_chars: '🔏', suspicious_extension: '📁', long_query: '📋',
            blocklist: '🚫', ai_model: '🧠',
        };
        return icons[type] || '⚠️';
    }

    function getEducationalTip(level, flags) {
        const tips = {
            critical: 'This site has multiple phishing indicators. Do NOT enter any credentials. Phishing sites often mimic legitimate companies to steal your data.',
            high: 'This link shows strong signs of phishing. Be very cautious. Verify the URL carefully before proceeding.',
            medium: 'Some suspicious patterns detected. Double-check this is the site you intend to visit.',
            low: 'Minor concerns only. Always verify URLs before entering sensitive information.',
        };
        const flagTips = {
            homograph: 'Homograph attacks use visually identical characters from different alphabets — e.g., Cyrillic "а" looks exactly like Latin "a".',
            brand_impersonation: 'Attackers copy the look of trusted brands. Always check the exact domain name in your browser address bar.',
            typosquatting: 'Typosquatting registers domains nearly identical to real sites, betting you\'ll mistype the URL.',
            ip_address: 'Legitimate websites use domain names, not raw IP addresses. IPs in URLs are a classic phishing tactic.',
        };
        const firstSpecial = flags.find(f => flagTips[f.type]);
        return firstSpecial ? flagTips[firstSpecial.type] : (tips[level] || tips.medium);
    }

    // ---------- Tooltip Management ----------
    function createTooltip(x, y, htmlContent) {
        removeTooltip();
        const div = document.createElement('div');
        div.id = 'aegis-tooltip';
        div.innerHTML = htmlContent;
        document.body.appendChild(div);
        positionTooltip(div, x, y);
        currentTooltip = div;

        // Wire up close button
        const closeBtn = div.querySelector('#aegis-close');
        if (closeBtn) closeBtn.addEventListener('click', removeTooltip);

        // Wire up block button
        const blockBtn = div.querySelector('#aegis-block-btn');
        if (blockBtn) {
            blockBtn.addEventListener('click', () => {
                const h = blockBtn.dataset.hostname;
                chrome.runtime.sendMessage({ type: 'ADD_TO_BLOCKLIST', hostname: h });
                showNotification(`🚫 ${h} blocked`, 'danger');
                removeTooltip();
            });
        }

        // Wire up proceed button
        const proceedBtn = div.querySelector('#aegis-proceed-btn');
        if (proceedBtn) {
            proceedBtn.addEventListener('click', () => {
                window.open(decodeURIComponent(proceedBtn.dataset.url), '_blank');
                removeTooltip();
            });
        }

        return div;
    }

    function positionTooltip(el, x, y) {
        const w = Math.min(380, window.innerWidth - 32);
        el.style.width = w + 'px';
        let left = x + 16;
        let top = y + 16;
        if (left + w > window.innerWidth - 16) left = x - w - 8;
        if (top + 320 > window.innerHeight) top = y - 320;
        el.style.left = Math.max(8, left) + 'px';
        el.style.top = Math.max(8, top) + 'px';
    }

    function removeTooltip() {
        if (currentTooltip) {
            currentTooltip.remove();
            currentTooltip = null;
        }
    }

    // ---------- Notification Toast ----------
    function showNotification(msg, type = 'info') {
        const el = document.createElement('div');
        el.className = `aegis-notif aegis-notif-${type}`;
        el.textContent = msg;
        document.body.appendChild(el);
        setTimeout(() => el.classList.add('aegis-notif-show'), 10);
        setTimeout(() => { el.classList.remove('aegis-notif-show'); setTimeout(() => el.remove(), 400); }, 3500);
    }

    // ---------- Link Hover Handler ----------
    function getHoveredLink(e) {
        let el = e.target;
        while (el && el !== document.body) {
            if (el.tagName === 'A' && el.href && el.href.startsWith('http')) return el;
            el = el.parentElement;
        }
        return null;
    }

    let hoverTimer = null;
    let lastHoveredUrl = null;

    document.addEventListener('mouseover', (e) => {
        if (!settings.hoverEnabled) return;
        const link = getHoveredLink(e);
        if (!link) return;
        const url = link.href;
        if (url === lastHoveredUrl && currentTooltip) return;
        lastHoveredUrl = url;

        clearTimeout(hoverTimer);
        hoverTimer = setTimeout(() => {
            showAnalysis(url, e.clientX + window.scrollX, e.clientY + window.scrollY);
        }, 50); // Improved responsiveness
    });

    document.addEventListener('mouseout', (e) => {
        const link = getHoveredLink(e);
        if (!link) return;
        clearTimeout(hoverTimer);
        // Keep tooltip visible for 1.5s so user can interact with it
        setTimeout(() => {
            if (currentTooltip && !currentTooltip.matches(':hover')) removeTooltip();
        }, 1500);
    });

    document.addEventListener('mousemove', (e) => {
        if (currentTooltip && currentTooltip.matches(':hover')) return;
    });

    // Keep tooltip alive when mouse is on it
    document.addEventListener('mouseover', (e) => {
        if (currentTooltip && currentTooltip.contains(e.target)) return;
    });

    function showAnalysis(url, x, y) {
        // Check cache first
        if (analysisCache.has(url)) {
            const cached = analysisCache.get(url);
            createTooltip(x, y, buildTooltipHTML(cached, false));
            return;
        }

        // Show loading
        createTooltip(x, y, buildTooltipHTML(null, true));

        // Quick regex check while waiting
        const quickHits = quickRegexCheck(url);
        if (quickHits.length > 0) {
            // Show partial result
            const quickScore = quickHits.reduce((s, h) => s + h.weight, 0);
            if (quickScore >= settings.blockThreshold) {
                // Quick block feedback
                showNotification('⚠️ AegisAI: Suspicious link detected!', 'warning');
            }
        }

        // Send to background for full analysis
        if (pendingAnalysis.has(url)) return;
        pendingAnalysis.set(url, true);

        chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url }, (result) => {
            pendingAnalysis.delete(url);
            if (chrome.runtime.lastError || !result) return;
            analysisCache.set(url, result);
            if (currentTooltip && lastHoveredUrl === url) {
                const newHTML = buildTooltipHTML(result, false);
                currentTooltip.innerHTML = newHTML;
                // Re-wire buttons
                const closeBtn = currentTooltip.querySelector('#aegis-close');
                if (closeBtn) closeBtn.addEventListener('click', removeTooltip);
                const blockBtn = currentTooltip.querySelector('#aegis-block-btn');
                if (blockBtn) blockBtn.addEventListener('click', () => {
                    chrome.runtime.sendMessage({ type: 'ADD_TO_BLOCKLIST', hostname: blockBtn.dataset.hostname });
                    showNotification(`🚫 ${blockBtn.dataset.hostname} blocked`, 'danger');
                    removeTooltip();
                });
                const proceedBtn = currentTooltip.querySelector('#aegis-proceed-btn');
                if (proceedBtn) proceedBtn.addEventListener('click', () => {
                    window.open(decodeURIComponent(proceedBtn.dataset.url), '_blank');
                    removeTooltip();
                });
            }
        });
    }

    // ---------- Current Page Analysis ----------
    function analyzeCurrentPage() {
        const url = window.location.href;
        if (!url.startsWith('http')) return;

        chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url }, (result) => {
            if (chrome.runtime.lastError || !result) return;
            analysisCache.set(url, result);

            // Show ambient risk indicator for current page
            if (result.score >= 45) {
                injectAmbientRisk(result);
            }
        });
    }

    function injectAmbientRisk(result) {
        const existing = document.getElementById('aegis-ambient');
        if (existing) existing.remove();

        const colors = { medium: '#f59e0b', high: '#ef4444', critical: '#a855f7' };
        const color = colors[result.level] || '#f59e0b';

        const div = document.createElement('div');
        div.id = 'aegis-ambient';
        div.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      pointer-events: none; z-index: 2147483640;
      box-shadow: inset 0 0 60px 20px ${color}44;
      border: 2px solid ${color}66;
      animation: aegis-pulse 2s ease-in-out infinite;
    `;
        document.body.appendChild(div);
        if (!document.getElementById('aegis-ambient-style')) {
            const s = document.createElement('style');
            s.id = 'aegis-ambient-style';
            s.textContent = `@keyframes aegis-pulse { 0%,100%{opacity:.5} 50%{opacity:1} }`;
            document.head.appendChild(s);
        }
    }

    // ---------- Load Settings ----------
    function loadSettings() {
        chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, (s) => {
            if (s) settings = { ...settings, ...s };
        });
    }

    // ---------- Click Interception for High-Risk Links ----------
    document.addEventListener('click', (e) => {
        const link = getHoveredLink(e);
        if (!link) return;
        const url = link.href;
        if (!url || !url.startsWith('http')) return;

        const cached = analysisCache.get(url);
        if (cached && cached.score >= (settings.blockThreshold || 70)) {
            e.preventDefault();
            e.stopPropagation();
            chrome.runtime.sendMessage({ type: 'BLOCK_PAGE', url, result: cached });
            const encoded = encodeURIComponent(JSON.stringify(cached));
            window.location.href = chrome.runtime.getURL(`blocked.html?data=${encoded}`);
        }
    }, true);

    // ---------- Init ----------
    loadSettings();
    analyzeCurrentPage();

    // Listen for settings updates
    chrome.storage.onChanged.addListener((changes) => {
        if (changes.settings) settings = { ...settings, ...changes.settings.newValue };
    });

    console.log('[AegisAI] Content script loaded on', window.location.hostname);
})();
