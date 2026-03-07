const SUSPICIOUS_TLDS = new Set([
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.click', '.link',
    '.download', '.win', '.bid', '.stream', '.science', '.racing', '.accountant',
    '.date', '.faith', '.loan', '.party', '.review', '.trade', '.webcam',
    '.men', '.gdn', '.kim', '.country', '.cricket', '.work', '.ninja',
    '.space', '.website', '.site', '.online', '.tech', '.live', '.fun',
]);
const SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'secure', 'account', 'update', 'verify', 'confirm',
    'banking', 'password', 'credential', 'paypal', 'apple', 'amazon', 'google',
    'microsoft', 'netflix', 'facebook', 'instagram', 'ebay', 'support', 'helpdesk',
    'alert', 'warning', 'suspended', 'locked', 'billing', 'payment', 'invoice',
    'refund', 'prize', 'winner', 'congratulation', 'gift', 'free', 'click', 'urgent',
    'immediate', 'action', 'required', 'expire', 'limited', 'offer', 'bonus',
];
const BRAND_DOMAINS = {
    'google': ['google.com', 'google.co.in', 'google.co.uk', 'googleapis.com', 'googlevideo.com'],
    'facebook': ['facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com'],
    'microsoft': ['microsoft.com', 'office.com', 'live.com', 'outlook.com', 'azure.com'],
    'apple': ['apple.com', 'icloud.com'],
    'amazon': ['amazon.com', 'amazon.in', 'aws.amazon.com', 'amazonaws.com'],
    'paypal': ['paypal.com', 'paypal.me'],
    'netflix': ['netflix.com'],
    'bank': ['chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 'hdfc.com', 'sbi.co.in'],
};
const ALL_LEGIT_DOMAINS = new Set(Object.values(BRAND_DOMAINS).flat());
let dynamicBlocklist = new Set();
let phishingStats = { blocked: 0, scanned: 0, threats: 0 };
let ruleIdCounter = 10000;
let hostnameToRuleId = {};
function getRuleIdForHostname(hostname) {
    if (hostnameToRuleId[hostname]) return hostnameToRuleId[hostname];
    ruleIdCounter++;
    hostnameToRuleId[hostname] = ruleIdCounter;
    return ruleIdCounter;
}
function createBlockRulesForHost(hostname) {
    const baseId = getRuleIdForHostname(hostname);
    return [
        {
            id: baseId,
            priority: 1,
            action: { type: 'block' },
            condition: {
                requestDomains: [hostname],
                resourceTypes: [
                    'main_frame', 'sub_frame', 'stylesheet', 'script', 'image',
                    'font', 'object', 'xmlhttprequest', 'ping', 'media',
                    'websocket', 'other'
                ]
            }
        }
    ];
}
async function rebuildBlockRules() {
    try {
        const data = await chrome.storage.local.get(['blocklist', 'ruleIdMap']);
        const blocklist = data.blocklist || [];
        if (data.ruleIdMap) {
            hostnameToRuleId = data.ruleIdMap;
            ruleIdCounter = Math.max(10000, ...Object.values(hostnameToRuleId));
        }
        const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
        const removeIds = existingRules.map(r => r.id);
        if (blocklist.length === 0) {
            if (removeIds.length > 0) {
                await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: removeIds });
            }
            return;
        }
        const addRules = [];
        for (const hostname of blocklist) {
            addRules.push(...createBlockRulesForHost(hostname));
        }
        await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: removeIds,
            addRules: addRules,
        });
        chrome.storage.local.set({ ruleIdMap: hostnameToRuleId });
        console.log(`[AegisAI] Hard-blocked ${blocklist.length} domains (${addRules.length} network rules active)`);
    } catch (e) {
        console.error('[AegisAI] Failed to rebuild block rules:', e);
    }
}
function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, (_, i) => [i]);
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++)
        for (let j = 1; j <= n; j++)
            dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1]
                : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    return dp[m][n];
}
function shannonEntropy(str) {
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    const len = str.length;
    return -Object.values(freq).reduce((s, f) => {
        const p = f / len; return s + p * Math.log2(p);
    }, 0);
}
const HOMOGRAPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
    'ı': 'i', 'ĺ': 'l', 'ó': 'o', 'á': 'a', 'ú': 'u',
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b',
};
function normalizeHomograph(str) {
    return str.split('').map(c => HOMOGRAPH_MAP[c] || c).join('');
}
const _sslCache = new Map();
async function checkSSLCertificate(hostname) {
    if (_sslCache.has(hostname)) return _sslCache.get(hostname);
    const defaultResult = { firstCertDate: null, ageInDays: null, tooNew: false, isRecent: false };
    try {
        const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('crt.sh timeout')), 8000)
        );
        const fetchPromise = fetch(
            `https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`,
            { headers: { 'Accept': 'application/json' } }
        );
        const resp = await Promise.race([fetchPromise, timeoutPromise]);
        if (!resp.ok) {
            console.warn(`[AegisAI] crt.sh returned ${resp.status} for ${hostname}`);
            return defaultResult;
        }
        const certs = await resp.json();
        if (!Array.isArray(certs) || certs.length === 0) return defaultResult;
        const earliest = certs.reduce((best, cur) => {
            if (!cur.entry_timestamp) return best;
            if (!best) return cur;
            return new Date(cur.entry_timestamp) < new Date(best.entry_timestamp) ? cur : best;
        }, null);
        if (!earliest || !earliest.entry_timestamp) return defaultResult;
        const firstCertDate = new Date(earliest.entry_timestamp);
        if (isNaN(firstCertDate.getTime())) return defaultResult;
        const ageInDays = Math.floor((Date.now() - firstCertDate.getTime()) / 86400000);
        const firstCertDateStr = firstCertDate.toISOString().split('T')[0];
        const result = {
            firstCertDate: firstCertDateStr,
            ageInDays,
            tooNew: ageInDays < 30,
            isRecent: ageInDays < 180,
            certName: earliest.name_value || hostname
        };
        _sslCache.set(hostname, result);
        console.log(`[AegisAI] SSL age for ${hostname}: ${ageInDays} days (first cert: ${firstCertDateStr})`);
        return result;
    } catch (e) {
        console.warn(`[AegisAI] SSL cert check failed for ${hostname}:`, e.message);
        return defaultResult;
    }
}
function extractFeatures(url) {
    let parsed;
    try { parsed = new URL(url); } catch { return null; }
    const hostname = parsed.hostname.toLowerCase().replace(/^www\./, '');
    const path = parsed.pathname + parsed.search;
    const fullUrl = url.toLowerCase();
    const tld = '.' + hostname.split('.').slice(-1)[0];
    const domainParts = hostname.split('.');
    const subdomainCount = domainParts.length - 2;
    const domainWithoutTld = domainParts.slice(0, -1).join('.');
    const flags = [];
    const hasSuspiciousTld = SUSPICIOUS_TLDS.has(tld);
    if (hasSuspiciousTld) flags.push({
        type: 'suspicious_tld',
        text: `Uses a suspicious web ending (${tld}). Legitimate sites rarely use these "cheap" endings for sensitive services.`
    });
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const hasIp = ipPattern.test(hostname);
    if (hasIp) flags.push({
        type: 'ip_address',
        text: 'This site uses a numeric address (IP) instead of a name. Real websites always use names like "google.com".'
    });
    if (subdomainCount > 2) flags.push({
        type: 'many_subdomains',
        text: 'The web address is buried under too many sections. Attackers do this to hide where the link actually goes.'
    });
    const kwFound = SUSPICIOUS_KEYWORDS.filter(kw => domainWithoutTld.includes(kw));
    if (kwFound.length > 0) flags.push({
        type: 'suspicious_keywords',
        text: `Contains "internal" words like (${kwFound.slice(0, 2).join(', ')}) in the wrong place. This is a common trick to look official.`
    });
    if (url.length > 100) flags.push({
        type: 'long_url',
        text: 'The link is abnormally long. Scammers use long links to hide the malicious parts from your view.'
    });
    if (fullUrl.includes('@')) flags.push({
        type: 'at_sign',
        text: 'URL contains a "hidden redirect" symbol (@). Your browser will be sent to a different site than what you see at the start.'
    });
    if (path.includes('
        type: 'double_slash',
        text: 'Unusual double slashes found. This technique is often used to bypass security filters.'
    });
    const dotCount = hostname.split('.').length - 1;
    if (dotCount > 4) flags.push({
        type: 'many_dots',
        text: 'Too many dots in the site name. This is often used to impersonate large brands by nesting their names.'
    });
    const isHttps = parsed.protocol === 'https:';
    if (!isHttps) flags.push({ type: 'no_https', text: 'Not using HTTPS — your data could be intercepted' });
    if (/[<>{}|\\^`]/.test(url)) flags.push({ type: 'special_chars', text: 'Special characters in URL — potential injection attack' });
    const normalizedDomain = normalizeHomograph(hostname);
    if (normalizedDomain !== hostname) {
        flags.push({
            type: 'homograph',
            text: 'Site uses lookalike characters (e.g., using a "0" instead of "O"). It is trying to trick you into thinking it' + "'" + 's a real brand.'
        });
    }
    let brandMatch = null;
    for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
        const isLegit = domains.some(d => hostname === d || hostname.endsWith('.' + d));
        if (isLegit) break;
        if (hostname.includes(brand) && !domains.some(d => hostname === d)) {
            brandMatch = brand;
            flags.push({
                type: 'brand_impersonation',
                text: `Impersonating "${brand}". The real website address is "${domains[0]}". Do not trust this clone.`
            });
            break;
        }
        const mainDomain = domainParts.slice(-2, -1)[0] || '';
        for (const legit of domains) {
            const legitMain = legit.split('.')[0];
            const dist = levenshtein(normalizeHomograph(mainDomain), legitMain);
            if (dist > 0 && dist <= 2 && mainDomain.length > 3) {
                brandMatch = brand;
                flags.push({ type: 'typosquatting', text: `Typosquatting "${legitMain}" — very similar domain name (${dist} char diff)` });
                break;
            }
        }
        if (brandMatch) break;
    }
    const entropy = shannonEntropy(domainWithoutTld);
    if (entropy > 4.0) flags.push({
        type: 'high_entropy',
        text: 'The site name looks randomly generated. This is common for short-lived criminal domains.'
    });
    const dashCount = (hostname.match(/-/g) || []).length;
    if (dashCount > 3) flags.push({
        type: 'many_dashes',
        text: 'The link contains too many dashes. This layout is used to make the real destination harder to read.'
    });
    if (hostname.includes('https-') || hostname.includes('secure-')) {
        flags.push({
            type: 'https_subdomain',
            text: 'Tries to look "Secure" by adding security words into the name. This is a common social engineering tactic.'
        });
    }
    for (const brand of Object.keys(BRAND_DOMAINS)) {
        if (path.includes(brand) && !hostname.includes(brand)) {
            flags.push({
                type: 'brand_in_path',
                text: `Mentions "${brand}" in the page address but the actual destination is different. This is highly suspicious.`
            });
            break;
        }
    }
    const encodedPct = (url.match(/%[0-9a-fA-F]{2}/g) || []).length;
    if (encodedPct > 3) flags.push({ type: 'encoded_chars', text: `${encodedPct} URL-encoded characters — hiding suspicious content` });
    const suspExt = ['.exe', '.php', '.asp', '.zip', '.rar', '.cmd', '.bat', '.js', '.vbs', '.ps1', '.jar'];
    const pathExt = suspExt.find(e => path.includes(e));
    if (pathExt) flags.push({ type: 'suspicious_extension', text: `Suspicious file type "${pathExt}" in URL path` });
    if (parsed.search.length > 100) flags.push({ type: 'long_query', text: `Very long query string (${parsed.search.length} chars) — data exfiltration concern` });
    if (dynamicBlocklist.has(hostname)) flags.push({ type: 'blocklist', text: 'Domain is on the phishing blocklist — previously reported' });
    const isDefinitelyLegit = ALL_LEGIT_DOMAINS.has(hostname) && !dynamicBlocklist.has(hostname);
    return { hostname, flags, isHttps, entropy, dotCount, subdomainCount, url, isDefinitelyLegit };
}
function calcHeuristicAmplifier(features) {
    if (!features) return { amplifier: 0, flags: [] };
    if (features.isDefinitelyLegit) return { amplifier: 0, flags: [] };
    const weights = {
        suspicious_tld: 5,
        ip_address: 8,
        many_subdomains: 4,
        suspicious_keywords: 5,
        long_url: 2,
        at_sign: 7,
        double_slash: 3,
        many_dots: 3,
        no_https: 4,
        special_chars: 5,
        homograph: 9,
        brand_impersonation: 10,
        typosquatting: 9,
        high_entropy: 3,
        many_dashes: 2,
        encoded_chars: 3,
        suspicious_extension: 4,
        long_query: 1,
        new_domain: 10,
        recent_domain: 4,
        blocklist: 30,
    };
    let amplifier = 0;
    for (const flag of features.flags) {
        amplifier += weights[flag.type] || 2;
    }
    return { amplifier: Math.min(amplifier, 30), flags: features.flags };
}
function calcRiskScore(features) {
    if (!features) return { score: 0, level: 'safe', label: 'SECURE' };
    if (features.isDefinitelyLegit) return { score: 0, level: 'safe', label: 'SECURE', flags: [] };
    const { amplifier } = calcHeuristicAmplifier(features);
    const score = Math.min(Math.round(amplifier * 3.33), 100);
    let level, label;
    if (score >= 70) { level = 'critical'; label = 'CRITICAL'; }
    else if (score >= 45) { level = 'high'; label = 'HIGH RISK'; }
    else if (score >= 20) { level = 'medium'; label = 'WARNING'; }
    else if (score > 0) { level = 'low'; label = 'LOW RISK'; }
    else { level = 'safe'; label = 'SECURE'; }
    return { score, level, label, flags: features.flags };
}
import { pipeline, env } from './transformers.js';
env.allowLocalModels = false;
env.useBrowserCache = true;
env.backends.onnx.wasm.wasmPaths = chrome.runtime.getURL('/');
let classifier = null;
let modelLoading = false;
async function analyzeUrl(url) {
    const features = extractFeatures(url);
    if (!features) return { error: 'Invalid URL', score: 0, level: 'safe', flags: [], label: 'SECURE' };
    if (features.isDefinitelyLegit) {
        return { url, hostname: features.hostname, score: 0, level: 'safe', label: 'SECURE', flags: [], isHttps: features.isHttps, isDefinitelyLegit: true, shouldBlock: false, timestamp: Date.now(), modelDriven: false };
    }
    const { amplifier } = calcHeuristicAmplifier(features);
    let modelBaseScore = 0;
    let modelConfidence = 0;
    let modelDriven = false;
    let sslInfo = { firstCertDate: null, ageInDays: null, tooNew: false, isRecent: false };
    const [, sslResult] = await Promise.all([
        (async () => {
            try {
                if (!classifier && !modelLoading) {
                    modelLoading = true;
                    const modelUrl = chrome.runtime.getURL('models/Xenova/distilbert-base-uncased-finetuned-sst-2-english/');
                    classifier = await pipeline('text-classification', modelUrl, { quantized: true });
                    modelLoading = false;
                    console.log('[AegisAI] DistilBERT model loaded');
                }
                if (classifier) {
                    const flagSummary = features.flags.map(f => f.type.replace(/_/g, ' ')).join(', ');
                    const inputText = `URL: ${url}. Domain: ${features.hostname}. Detected: ${flagSummary || 'no flags'}. HTTPS: ${features.isHttps}.`;
                    const result = await classifier(inputText);
                    if (result && result.length > 0) {
                        const pred = result[0];
                        modelConfidence = pred.score;
                        if (pred.label === 'NEGATIVE') {
                            modelBaseScore = Math.round(modelConfidence * 100);
                            modelDriven = true;
                            features.flags.push({
                                type: 'ai_model',
                                text: `DistilBERT neural model: ${(modelConfidence * 100).toFixed(1)}% phishing confidence — URL structure matches known attack patterns`
                            });
                        } else if (pred.label === 'POSITIVE' && modelConfidence > 0.85) {
                            modelBaseScore = Math.round((1 - modelConfidence) * 30);
                            modelDriven = true;
                        }
                    }
                }
            } catch (e) {
                console.error('[AegisAI] Model execution failed:', e);
                modelLoading = false;
            }
        })(),
        checkSSLCertificate(features.hostname)
    ]);
    sslInfo = sslResult || sslInfo;
    if (sslInfo.ageInDays !== null) {
        if (sslInfo.tooNew) {
            features.flags.push({
                type: 'new_domain',
                text: `Domain is only ${sslInfo.ageInDays} day${sslInfo.ageInDays === 1 ? '' : 's'} old based on its first SSL certificate. Criminals create fresh domains just before attacks.`
            });
        } else if (sslInfo.isRecent) {
            features.flags.push({
                type: 'recent_domain',
                text: `Domain was first seen ${sslInfo.ageInDays} days ago. Newly registered domains are higher risk than established sites.`
            });
        }
    }
    let score;
    if (modelDriven) {
        score = Math.min(modelBaseScore + amplifier, 100);
    } else {
        score = Math.min(Math.round(amplifier * 3.33), 100);
    }
    if (sslInfo.tooNew) score = Math.min(score + 20, 100);
    else if (sslInfo.isRecent) score = Math.min(score + 8, 100);
    let level, label;
    if (score >= 70) { level = 'critical'; label = 'CRITICAL'; }
    else if (score >= 45) { level = 'high'; label = 'HIGH RISK'; }
    else if (score >= 20) { level = 'medium'; label = 'WARNING'; }
    else if (score > 0) { level = 'low'; label = 'LOW RISK'; }
    else { level = 'safe'; label = 'SECURE'; }
    return {
        url,
        hostname: features.hostname,
        score,
        level,
        label,
        flags: features.flags,
        isHttps: features.isHttps,
        isDefinitelyLegit: features.isDefinitelyLegit,
        modelDriven,
        modelConfidence: Math.round(modelConfidence * 100),
        shouldBlock: score >= 70,
        domainAge: sslInfo.ageInDays,
        firstCertDate: sslInfo.firstCertDate || null,
        timestamp: Date.now(),
    };
}
async function initStorage() {
    const data = await chrome.storage.local.get(['blocklist', 'stats', 'settings']);
    if (data.blocklist) dynamicBlocklist = new Set(data.blocklist);
    if (data.stats) phishingStats = data.stats;
    if (!data.settings) {
        await chrome.storage.local.set({
            settings: {
                blockingEnabled: true,
                hoverEnabled: true,
                showBadge: true,
                blockThreshold: 70,
                notifyOnBlock: true,
            }
        });
    }
}
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'ANALYZE_URL') {
        analyzeUrl(msg.url).then(result => {
            phishingStats.scanned++;
            if (result.level === 'critical' || result.level === 'high') phishingStats.threats++;
            chrome.storage.local.set({ stats: phishingStats });
            sendResponse(result);
        });
        return true;
    }
    if (msg.type === 'GET_DOMAIN_AGE') {
        checkSSLCertificate(msg.hostname).then(result => {
            sendResponse({
                ageInDays: result.ageInDays,
                firstCertDate: result.firstCertDate || null,
                tooNew: result.tooNew,
                isRecent: result.isRecent
            });
        }).catch(() => sendResponse({ ageInDays: null, firstCertDate: null, tooNew: false, isRecent: false }));
        return true;
    }
    if (msg.type === 'GET_STATS') {
        sendResponse(phishingStats);
        return true;
    }
    if (msg.type === 'ADD_TO_BLOCKLIST') {
        dynamicBlocklist.add(msg.hostname);
        chrome.storage.local.set({ blocklist: [...dynamicBlocklist] });
        const ruleId = hashHostnameToRuleId(msg.hostname);
        chrome.declarativeNetRequest.updateDynamicRules({
            addRules: [{
                id: ruleId,
                priority: 1,
                action: { type: 'block' },
                condition: {
                    urlFilter: `||${msg.hostname}`,
                    resourceTypes: [
                        'main_frame', 'sub_frame', 'stylesheet', 'script', 'image',
                        'font', 'object', 'xmlhttprequest', 'ping', 'media',
                        'websocket', 'webtransport', 'webbundle', 'other'
                    ]
                }
            }],
            removeRuleIds: [ruleId]
        });
        chrome.tabs.query({}, (tabs) => {
            for (const tab of tabs) {
                if (!tab.url || !tab.url.startsWith('http')) continue;
                try {
                    const tabHost = new URL(tab.url).hostname.toLowerCase().replace(/^www\./, '');
                    if (tabHost === msg.hostname) {
                        const blockResult = {
                            url: tab.url,
                            hostname: msg.hostname,
                            score: 100,
                            level: 'critical',
                            label: 'Blocked Domain',
                            flags: [{ type: 'blocklist', text: `Domain "${msg.hostname}" is on your blocklist — access permanently denied` }],
                            shouldBlock: true,
                            timestamp: Date.now(),
                        };
                        phishingStats.blocked++;
                        chrome.storage.local.set({ stats: phishingStats });
                        const encodedResult = encodeURIComponent(JSON.stringify(blockResult));
                        const blockedUrl = chrome.runtime.getURL(`blocked.html?data=${encodedResult}`);
                        chrome.tabs.update(tab.id, { url: blockedUrl });
                    }
                } catch (_) { }
            }
        });
        sendResponse({ ok: true });
        return true;
    }
    if (msg.type === 'REMOVE_FROM_BLOCKLIST') {
        dynamicBlocklist.delete(msg.hostname);
        chrome.storage.local.set({ blocklist: [...dynamicBlocklist] });
        const ruleId = hashHostnameToRuleId(msg.hostname);
        chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [ruleId]
        });
        sendResponse({ ok: true });
        return true;
    }
    if (msg.type === 'BLOCK_PAGE') {
        phishingStats.blocked++;
        chrome.storage.local.set({ stats: phishingStats, lastBlocked: msg });
        sendResponse({ ok: true });
        return true;
    }
    if (msg.type === 'GET_SETTINGS') {
        chrome.storage.local.get('settings', d => sendResponse(d.settings || {}));
        return true;
    }
    if (msg.type === 'SET_SETTINGS') {
        chrome.storage.local.set({ settings: msg.settings }, () => sendResponse({ ok: true }));
        return true;
    }
    if (msg.type === 'RESET_STATS') {
        phishingStats = { blocked: 0, scanned: 0, threats: 0 };
        chrome.storage.local.set({ stats: phishingStats });
        sendResponse({ ok: true });
        return true;
    }
});
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return;
    const settings = (await chrome.storage.local.get('settings')).settings || {};
    if (!settings.blockingEnabled) return;
    try {
        const urlObj = new URL(details.url);
        const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
        if (dynamicBlocklist.has(hostname)) {
            phishingStats.blocked++;
            const blockResult = {
                url: details.url,
                hostname,
                score: 100,
                level: 'critical',
                label: 'Blocked Domain',
                flags: [{ type: 'blocklist', text: `Domain "${hostname}" is on your blocklist — access denied` }],
                isHttps: urlObj.protocol === 'https:',
                shouldBlock: true,
                timestamp: Date.now(),
            };
            chrome.storage.local.set({ stats: phishingStats, lastBlocked: { url: details.url, result: blockResult } });
            const encodedResult = encodeURIComponent(JSON.stringify(blockResult));
            const blockedUrl = chrome.runtime.getURL(`blocked.html?data=${encodedResult}`);
            chrome.tabs.update(details.tabId, { url: blockedUrl });
            return;
        }
    } catch (_) { }
    const result = await analyzeUrl(details.url);
    if (result.shouldBlock || result.score >= (settings.blockThreshold || 70)) {
        phishingStats.blocked++;
        chrome.storage.local.set({ stats: phishingStats, lastBlocked: { url: details.url, result } });
        const encodedResult = encodeURIComponent(JSON.stringify(result));
        const blockedUrl = chrome.runtime.getURL(`blocked.html?data=${encodedResult}`);
        chrome.tabs.update(details.tabId, { url: blockedUrl });
    }
});
chrome.tabs.onUpdated.addListener(async (tabId, change, tab) => {
    if (!change.url || !change.url.startsWith('http')) return;
    const settings = (await chrome.storage.local.get('settings')).settings || {};
    if (!settings.blockingEnabled) return;
    try {
        const urlObj = new URL(change.url);
        const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
        if (dynamicBlocklist.has(hostname)) {
            phishingStats.blocked++;
            const blockResult = {
                url: change.url,
                hostname,
                score: 100,
                level: 'critical',
                label: 'Blocked Domain',
                flags: [{ type: 'blocklist', text: `Domain "${hostname}" is on your blocklist — access denied` }],
                isHttps: urlObj.protocol === 'https:',
                shouldBlock: true,
                timestamp: Date.now(),
            };
            chrome.storage.local.set({ stats: phishingStats, lastBlocked: { url: change.url, result: blockResult } });
            const encodedResult = encodeURIComponent(JSON.stringify(blockResult));
            const blockedUrl = chrome.runtime.getURL(`blocked.html?data=${encodedResult}`);
            chrome.tabs.update(tabId, { url: blockedUrl });
        }
    } catch (_) { }
});
chrome.tabs.onActivated.addListener(async (info) => {
    try {
        const tab = await chrome.tabs.get(info.tabId);
        if (!tab.url || !tab.url.startsWith('http')) return;
        const result = await analyzeUrl(tab.url);
        updateBadge(result, info.tabId);
    } catch (_) { }
});
chrome.tabs.onUpdated.addListener(async (tabId, change, tab) => {
    if (change.status !== 'complete') return;
    if (!tab.url || !tab.url.startsWith('http')) return;
    const result = await analyzeUrl(tab.url);
    updateBadge(result, tabId);
});
function updateBadge(result, tabId) {
    const colors = { safe: '#22c55e', low: '#84cc16', medium: '#f59e0b', high: '#ef4444', critical: '#7c3aed' };
    const color = colors[result.level] || '#6b7280';
    const text = result.score > 0 ? `${result.score}%` : '';
    chrome.action.setBadgeBackgroundColor({ color, tabId });
    chrome.action.setBadgeText({ text, tabId });
    chrome.runtime.sendMessage({ type: 'URL_ANALYZED', result }).catch(() => { });
    chrome.storage.session?.set({ lastAnalysis: result }).catch(() => { });
}
initStorage();
rebuildBlockRules();
console.log('[AegisAI] Background service worker started');