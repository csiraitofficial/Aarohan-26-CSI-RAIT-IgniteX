/**
 * ============================================================
 * PhishLens — Multi-Platform Phishing Detection Content Script
 * ============================================================
 *
 * PRIVACY-FIRST ARCHITECTURE
 * --------------------------
 * This extension runs ENTIRELY in the browser. There are:
 *   • NO backend servers
 *   • NO external API calls
 *   • NO data transmission of any kind
 *   • NO analytics or tracking
 *
 * Supported Platforms:
 *   • Gmail
 *   • Outlook Web (outlook.live.com, outlook.office.com, outlook.office365.com)
 *   • Yahoo Mail
 *   • iCloud Mail
 *   • WhatsApp Web
 *   • Telegram Web
 *
 * ============================================================
 */

(function PhishLens() {
  'use strict';

  // Prevent double-injection
  if (window.__PHISHLENS_LOADED__) return;
  window.__PHISHLENS_LOADED__ = true;

  console.log('[PhishLens] 🛡️ Extension loaded — privacy-first phishing detection active');

  // ═══════════════════════════════════════════════════════════
  // §1  CONSTANTS & CONFIG
  // ═══════════════════════════════════════════════════════════

  const CONFIG = {
    ONNX_THRESHOLD: 0.75,
    RISK_LOW_MAX: 2,
    RISK_MEDIUM_MAX: 5,
    WEIGHT_ONNX: 3,
    WEIGHT_URGENCY: 2,
    WEIGHT_FEAR: 2,
    WEIGHT_SUSPICIOUS_URL: 3,
    WEIGHT_AUTHORITY: 2,
    DEBOUNCE_MS: 1200,
    MAX_SENTENCES: 50,
    MIN_SENTENCE_LENGTH: 15,
    BATCH_SIZE: 5,
  };

  // ═══════════════════════════════════════════════════════════
  // §2  PLATFORM DETECTION
  // ═══════════════════════════════════════════════════════════

  const PLATFORMS = {
    gmail: {
      name: 'Gmail',
      hostnames: ['mail.google.com'],
      bodySelectors: ['.a3s.aiL'],
      readySelectors: ['[role="main"]', '.nH', '.AO'],
      quoteSelectors: ['.gmail_quote'],
      type: 'email',
    },
    outlook: {
      name: 'Outlook',
      hostnames: ['outlook.live.com', 'outlook.office.com', 'outlook.office365.com'],
      bodySelectors: [
        '[aria-label="Message body"]',
        '.allowTextSelection',
        '[role="document"]',
        '.wide-content-host',
        '.XbIp4.jmmB7',
      ],
      readySelectors: ['[role="main"]', '#app', '.lpc-hoverTarget'],
      quoteSelectors: ['.x_gmail_quote', '.gmail_quote', '#divRplyFwdMsg', '.BodyFragment'],
      type: 'email',
    },
    yahoo: {
      name: 'Yahoo Mail',
      hostnames: ['mail.yahoo.com'],
      bodySelectors: [
        '.msg-body',
        '.message-body',
        '[data-test-id="message-view-body-content"]',
        '.email-wrapped',
      ],
      readySelectors: ['#app', '[role="main"]', '.mail-app'],
      quoteSelectors: ['.yahoo_quoted', '.rawbody'],
      type: 'email',
    },
    icloud: {
      name: 'iCloud Mail',
      hostnames: ['www.icloud.com'],
      bodySelectors: [
        '.msg-body',
        '.message-body',
        '[role="document"]',
        '.letter-body',
      ],
      readySelectors: ['#wrapper', '.ui-app', '.mail-layout'],
      quoteSelectors: ['.quoted-text'],
      type: 'email',
    },
    whatsapp: {
      name: 'WhatsApp Web',
      hostnames: ['web.whatsapp.com'],
      bodySelectors: [
        '._amjw',
        '.message-in .copyable-text',
        '.message-out .copyable-text',
        '[data-pre-plain-text]',
        '.selectable-text',
      ],
      readySelectors: ['#app', '#main', '._aigv'],
      quoteSelectors: [],
      type: 'chat',
    },
    telegram: {
      name: 'Telegram Web',
      hostnames: ['web.telegram.org'],
      bodySelectors: [
        '.message-text-content',
        '.text-content',
        '.Message .text-entity',
        '.message .text',
      ],
      readySelectors: ['#telegram-app', '#app', '.chats-container', '.ChatList'],
      quoteSelectors: ['.reply-markup', '.WebPage'],
      type: 'chat',
    },
  };

  /**
   * Detect current platform based on hostname.
   */
  function detectPlatform() {
    const hostname = window.location.hostname.toLowerCase();
    for (const [key, platform] of Object.entries(PLATFORMS)) {
      if (platform.hostnames.some(h => hostname.includes(h))) {
        console.log(`[PhishLens] 🌐 Detected platform: ${platform.name}`);
        return { key, ...platform };
      }
    }
    console.log('[PhishLens] ❓ Unknown platform:', hostname);
    return null;
  }

  const currentPlatform = detectPlatform();
  if (!currentPlatform) return;

  // ═══════════════════════════════════════════════════════════
  // §3  TOGGLE STATE (chrome.storage)
  // ═══════════════════════════════════════════════════════════

  let _extensionEnabled = true;
  let _platformEnabled = true;

  /**
   * Load toggle state from chrome.storage.
   */
  async function loadToggleState() {
    return new Promise((resolve) => {
      if (typeof chrome === 'undefined' || !chrome.storage) {
        resolve();
        return;
      }
      chrome.storage.sync.get(['phishlens_global', `phishlens_${currentPlatform.key}`], (data) => {
        if (chrome.runtime.lastError) {
          resolve();
          return;
        }
        _extensionEnabled = data.phishlens_global !== false;
        _platformEnabled = data[`phishlens_${currentPlatform.key}`] !== false;
        console.log(`[PhishLens] Toggle state — Global: ${_extensionEnabled}, ${currentPlatform.name}: ${_platformEnabled}`);
        resolve();
      });
    });
  }

  /**
   * Listen for toggle changes from popup.
   */
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.onChanged.addListener((changes, namespace) => {
      if (namespace !== 'sync') return;
      if (changes.phishlens_global) {
        _extensionEnabled = changes.phishlens_global.newValue !== false;
        console.log(`[PhishLens] Global toggle: ${_extensionEnabled}`);
      }
      if (changes[`phishlens_${currentPlatform.key}`]) {
        _platformEnabled = changes[`phishlens_${currentPlatform.key}`].newValue !== false;
        console.log(`[PhishLens] ${currentPlatform.name} toggle: ${_platformEnabled}`);
      }
    });
  }

  function isEnabled() {
    return _extensionEnabled && _platformEnabled;
  }

  // ═══════════════════════════════════════════════════════════
  // §4  SENTENCE SPLITTER
  // ═══════════════════════════════════════════════════════════

  function splitSentences(text) {
    if (!text || typeof text !== 'string') return [];
    const abbrevs = /(?:Mr|Mrs|Ms|Dr|Prof|Jr|Sr|Inc|Ltd|Corp|Co|vs|etc|approx|dept|est|govt|i\.e|e\.g)\./gi;
    let processed = text.replace(abbrevs, (match) => match.replace(/\./g, '{{DOT}}'));
    processed = processed.replace(/https?:\/\/\S+/gi, (match) => match.replace(/\./g, '{{DOT}}'));
    processed = processed.replace(/[\w.-]+@[\w.-]+/gi, (match) => match.replace(/\./g, '{{DOT}}'));
    const raw = processed.split(/(?<=[.!?])\s+/);
    return raw
      .map((s) => s.replace(/\{\{DOT\}\}/g, '.').trim())
      .filter((s) => s.length > 5);
  }

  // ═══════════════════════════════════════════════════════════
  // §5  URL DETECTOR
  // ═══════════════════════════════════════════════════════════

  function analyzeURLs(sentence) {
    const result = { urls: [], hasShortener: false, hasSuspiciousTLD: false, hasDomainMismatch: false, brands: [] };
    const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
    const matches = sentence.match(urlRegex) || [];
    result.urls = matches;
    if (matches.length === 0) return result;

    const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in', 'rb.gy', 'cutt.ly', 'shorturl.at'];
    const suspiciousTLDs = ['.xyz', '.click', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.club', '.work', '.link', '.info', '.ru', '.cn', '.pw'];
    const knownBrands = ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'facebook', 'instagram', 'bank', 'chase', 'wells fargo', 'citibank', 'hsbc'];

    for (const url of matches) {
      let hostname = '';
      try { hostname = new URL(url).hostname.toLowerCase(); } catch (e) { hostname = url.toLowerCase(); }
      if (shorteners.some((s) => hostname.includes(s))) result.hasShortener = true;
      if (suspiciousTLDs.some((tld) => hostname.endsWith(tld))) result.hasSuspiciousTLD = true;
      const sentenceLower = sentence.toLowerCase();
      for (const brand of knownBrands) {
        if (sentenceLower.includes(brand) && !hostname.includes(brand.replace(/\s/g, ''))) {
          result.hasDomainMismatch = true;
          result.brands.push(brand);
        }
      }
    }
    return result;
  }

  // ═══════════════════════════════════════════════════════════
  // §6  RULE-BASED ENGINE
  // ═══════════════════════════════════════════════════════════

  const URGENCY_PATTERNS = [
    'urgent', 'immediately', 'act now', 'verify today',
    'account suspended', 'right away', 'as soon as possible',
    'within 24 hours', 'within 48 hours', 'expire', 'final warning',
    'last chance', 'time is running out', 'don\'t delay',
    'must respond', 'action required', 'respond immediately',
  ];

  const FEAR_PATTERNS = [
    'blocked', 'legal action', 'violation', 'penalty',
    'unauthorized', 'compromised', 'hacked', 'stolen',
    'permanent deletion', 'terminated', 'restricted',
    'closed', 'frozen', 'disabled', 'suspicious activity',
    'security breach', 'identity theft', 'lawsuit',
  ];

  const AUTHORITY_PATTERNS = [
    'bank', 'hr department', 'government', 'professor',
    'tax authority', 'irs', 'federal', 'police',
    'immigration', 'customs', 'compliance department',
    'security team', 'admin', 'helpdesk', 'it department',
    'account team', 'support team', 'verification team',
  ];

  function detectRules(sentence) {
    const lower = sentence.toLowerCase();
    const signals = {
      urgency: false, fear: false, authority: false, suspiciousURL: false,
      urlDetails: null, matchedUrgency: [], matchedFear: [], matchedAuthority: [],
    };

    for (const p of URGENCY_PATTERNS) { if (lower.includes(p)) { signals.urgency = true; signals.matchedUrgency.push(p); } }
    for (const p of FEAR_PATTERNS) { if (lower.includes(p)) { signals.fear = true; signals.matchedFear.push(p); } }
    for (const p of AUTHORITY_PATTERNS) { if (lower.includes(p)) { signals.authority = true; signals.matchedAuthority.push(p); } }

    const urlAnalysis = analyzeURLs(sentence);
    if (urlAnalysis.hasShortener || urlAnalysis.hasSuspiciousTLD || urlAnalysis.hasDomainMismatch) {
      signals.suspiciousURL = true;
      signals.urlDetails = urlAnalysis;
    }
    if (signals.authority && urlAnalysis.urls.length > 0 && urlAnalysis.hasDomainMismatch) {
      signals.authorityMismatch = true;
    }
    return signals;
  }

  // ═══════════════════════════════════════════════════════════
  // §7  ONNX MODEL INFERENCE
  // ═══════════════════════════════════════════════════════════

  let _onnxSession = null;
  let _modelLoadAttempted = false;
  let _modelAvailable = false;
  let _modelConfig = null;
  const INFERENCE_MAX_TOKENS = 128;

  function getExtensionURL(path) {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL) {
      return chrome.runtime.getURL(path);
    }
    return path;
  }

  async function loadModel() {
    if (_modelLoadAttempted) return _modelAvailable;
    _modelLoadAttempted = true;

    try {
      console.log('[PhishLens] 🧠 Loading ONNX model…');

      if (typeof ort !== 'undefined') {
        ort.env.wasm.wasmPaths = getExtensionURL('lib/');
      } else {
        console.warn('[PhishLens] ⚠️ ONNX Runtime Web (ort) not found — using fallback');
        return false;
      }

      // Load tokenizer vocabulary
      const vocabUrl = getExtensionURL('model/vocab.json');
      await PhishLensTokenizer.loadVocab(vocabUrl);

      // Load model config
      try {
        const configUrl = getExtensionURL('model/config.json');
        const configResp = await fetch(configUrl);
        if (configResp.ok) {
          _modelConfig = await configResp.json();
          console.log('[PhishLens] Model labels:', _modelConfig.id2label);
        }
      } catch (e) {
        console.warn('[PhishLens] Could not load model config, using defaults');
      }

      // Load ONNX model — try phishing_model.onnx first, fallback to model.onnx
      let modelUrl = getExtensionURL('model/phishing_model.onnx');
      try {
        const testResp = await fetch(modelUrl, { method: 'HEAD' });
        if (!testResp.ok) throw new Error('Not found');
      } catch (e) {
        console.log('[PhishLens] phishing_model.onnx not found, trying model.onnx');
        modelUrl = getExtensionURL('model/model.onnx');
      }

      _onnxSession = await ort.InferenceSession.create(modelUrl, {
        executionProviders: ['wasm'],
        graphOptimizationLevel: 'all',
      });

      _modelAvailable = true;
      console.log('[PhishLens] ✅ ONNX model loaded successfully');
      console.log('[PhishLens] Input names:', _onnxSession.inputNames);
      console.log('[PhishLens] Output names:', _onnxSession.outputNames);
      return true;
    } catch (err) {
      console.warn('[PhishLens] ⚠️ Could not load ONNX model — falling back to heuristic:', err.message);
      _modelAvailable = false;
      return false;
    }
  }

  function sigmoid(x) { return 1 / (1 + Math.exp(-x)); }

  function softmax(logits) {
    const maxLogit = Math.max(...logits);
    const exps = logits.map((l) => Math.exp(l - maxLogit));
    const sumExps = exps.reduce((a, b) => a + b, 0);
    return exps.map((e) => e / sumExps);
  }

  async function runONNXModelInference(sentence) {
    const { inputIds, attentionMask } = PhishLensTokenizer.tokenize(sentence, INFERENCE_MAX_TOKENS);
    const inputIdsTensor = new ort.Tensor('int64', BigInt64Array.from(inputIds.map(BigInt)), [1, inputIds.length]);
    const attentionMaskTensor = new ort.Tensor('int64', BigInt64Array.from(attentionMask.map(BigInt)), [1, attentionMask.length]);

    const feeds = {};
    const inputNames = _onnxSession.inputNames;
    if (inputNames.includes('input_ids')) feeds['input_ids'] = inputIdsTensor;
    else feeds[inputNames[0]] = inputIdsTensor;
    if (inputNames.includes('attention_mask')) feeds['attention_mask'] = attentionMaskTensor;
    else if (inputNames.length > 1) feeds[inputNames[1]] = attentionMaskTensor;

    const output = await _onnxSession.run(feeds);
    const outputName = _onnxSession.outputNames[0];
    const logits = Array.from(output[outputName].data);

    let phishingProb = 0;
    if (logits.length === 1) {
      phishingProb = sigmoid(Number(logits[0]));
    } else if (logits.length === 2) {
      const probs = softmax(logits.map(Number));
      let phishingIdx = 1;
      if (_modelConfig && _modelConfig.id2label) {
        for (const [idx, label] of Object.entries(_modelConfig.id2label)) {
          const l = String(label).toLowerCase();
          if (l.includes('phish') || l.includes('spam') || l.includes('malicious') || l === '1') {
            phishingIdx = parseInt(idx);
            break;
          }
        }
      }
      phishingProb = probs[phishingIdx];
    } else {
      const probs = softmax(logits.map(Number));
      phishingProb = Math.max(...probs.slice(1));
    }
    return phishingProb;
  }

  const PHISHING_NGRAMS = {
    'verify your account': 0.8, 'confirm your identity': 0.8,
    'update your information': 0.7, 'verify your identity': 0.85,
    'reset your password': 0.6, 'unusual sign-in': 0.7,
    'unauthorized access': 0.75, 'security alert': 0.6,
    'account has been': 0.65, 'account will be': 0.7,
    'click here': 0.5, 'click the link': 0.55,
    'click below': 0.5, 'act now': 0.7,
    'immediate action': 0.75, 'within 24 hours': 0.7,
    'failure to comply': 0.8, 'will be suspended': 0.8,
    'will be terminated': 0.8, 'will be deleted': 0.75,
    'permanently closed': 0.8, 'you have been selected': 0.85,
    'congratulations': 0.5, 'won a prize': 0.9,
    'claim your reward': 0.9, 'free gift': 0.8,
    'lottery winner': 0.95, 'wire transfer': 0.7,
    'bank account details': 0.8, 'credit card number': 0.85,
    'social security': 0.8, 'routing number': 0.8,
    'enter your password': 0.85, 'login credentials': 0.7,
    'sign in to verify': 0.8, 'your account password': 0.75,
  };

  function runFallbackInference(sentence) {
    const lower = sentence.toLowerCase();
    let maxScore = 0;
    let matchCount = 0;
    for (const [ngram, weight] of Object.entries(PHISHING_NGRAMS)) {
      if (lower.includes(ngram)) { maxScore = Math.max(maxScore, weight); matchCount++; }
    }
    if (matchCount >= 3) maxScore = Math.min(1.0, maxScore + 0.1);
    if (matchCount >= 2) maxScore = Math.min(1.0, maxScore + 0.05);
    return maxScore;
  }

  async function runONNXInference(sentence) {
    await loadModel();
    if (_modelAvailable && _onnxSession) {
      try { return await runONNXModelInference(sentence); }
      catch (err) { console.warn('[PhishLens] ONNX inference error, using fallback:', err.message); return runFallbackInference(sentence); }
    }
    return runFallbackInference(sentence);
  }

  // ═══════════════════════════════════════════════════════════
  // §8  RISK SCORER
  // ═══════════════════════════════════════════════════════════

  function calculateRisk(onnxProbability, ruleSignals) {
    let score = 0;
    const activeSignals = [];
    if (onnxProbability >= CONFIG.ONNX_THRESHOLD) { score += CONFIG.WEIGHT_ONNX; activeSignals.push('ai_detected'); }
    if (ruleSignals.urgency) { score += CONFIG.WEIGHT_URGENCY; activeSignals.push('urgency'); }
    if (ruleSignals.fear) { score += CONFIG.WEIGHT_FEAR; activeSignals.push('fear'); }
    if (ruleSignals.suspiciousURL) { score += CONFIG.WEIGHT_SUSPICIOUS_URL; activeSignals.push('suspicious_url'); }
    if (ruleSignals.authorityMismatch) { score += CONFIG.WEIGHT_AUTHORITY; activeSignals.push('authority_mismatch'); }
    else if (ruleSignals.authority) { score += 1; activeSignals.push('authority_claim'); }

    let level = 'low';
    if (score > CONFIG.RISK_MEDIUM_MAX) level = 'high';
    else if (score > CONFIG.RISK_LOW_MAX) level = 'medium';
    return { score, level, activeSignals };
  }

  // ═══════════════════════════════════════════════════════════
  // §9  EXPLANATION GENERATOR
  // ═══════════════════════════════════════════════════════════

  function generateExplanation(risk, ruleSignals, onnxProb) {
    const explanations = [];
    if (risk.activeSignals.includes('ai_detected')) {
      explanations.push('This sentence matches known phishing language patterns (AI confidence: ' + Math.round(onnxProb * 100) + '%).');
    }
    if (risk.activeSignals.includes('urgency') && risk.activeSignals.includes('suspicious_url')) {
      explanations.push('Combines urgency pressure with a suspicious link — a common phishing tactic.');
    } else if (risk.activeSignals.includes('urgency')) {
      explanations.push('Creates urgency pressure commonly used in phishing ("' + ruleSignals.matchedUrgency[0] + '").');
    }
    if (risk.activeSignals.includes('fear')) {
      explanations.push('Uses fear/threat language to manipulate the reader ("' + ruleSignals.matchedFear[0] + '").');
    }
    if (risk.activeSignals.includes('suspicious_url') && !risk.activeSignals.includes('urgency')) {
      const details = ruleSignals.urlDetails;
      if (details.hasShortener) explanations.push('Contains a URL shortener that obscures the real destination.');
      if (details.hasSuspiciousTLD) explanations.push('Links to a domain with a suspicious TLD commonly used in phishing.');
      if (details.hasDomainMismatch) explanations.push('The URL domain doesn\'t match the brand mentioned in the text.');
    }
    if (risk.activeSignals.includes('authority_mismatch')) {
      explanations.push('Claims authority ("' + ruleSignals.matchedAuthority[0] + '") but the linked domain doesn\'t match.');
    } else if (risk.activeSignals.includes('authority_claim')) {
      explanations.push('Claims to be from an authority figure ("' + ruleSignals.matchedAuthority[0] + '").');
    }
    if (explanations.length === 0) {
      if (risk.level === 'medium') explanations.push('This sentence shows some characteristics of phishing content.');
      else if (risk.level === 'high') explanations.push('Multiple phishing indicators detected in this sentence.');
    }
    return explanations.join(' ');
  }

  // ═══════════════════════════════════════════════════════════
  // §10  ANALYSIS PIPELINE
  // ═══════════════════════════════════════════════════════════

  async function analyzeEmail(text) {
    const sentences = splitSentences(text);
    const filtered = sentences
      .filter((s) => s.length >= CONFIG.MIN_SENTENCE_LENGTH)
      .slice(0, CONFIG.MAX_SENTENCES);

    const preScan = filtered.map((sentence) => ({ sentence, rules: detectRules(sentence) }));
    const results = [];

    for (let i = 0; i < preScan.length; i += CONFIG.BATCH_SIZE) {
      const batch = preScan.slice(i, i + CONFIG.BATCH_SIZE);
      const batchResults = await Promise.all(
        batch.map(async ({ sentence, rules }) => {
          const hasAnySignal = rules.urgency || rules.fear || rules.suspiciousURL || rules.authority;
          let onnxProb = 0;
          if (hasAnySignal) { onnxProb = await runONNXInference(sentence); }
          else { onnxProb = runFallbackInference(sentence); }
          const risk = calculateRisk(onnxProb, rules);
          const explanation = generateExplanation(risk, rules, onnxProb);
          return { sentence, onnxProbability: onnxProb, ruleSignals: rules, risk, explanation };
        })
      );
      results.push(...batchResults);
    }

    let maxRiskLevel = 'low';
    let totalScore = 0;
    let highCount = 0;
    let mediumCount = 0;
    for (const r of results) {
      totalScore += r.risk.score;
      if (r.risk.level === 'high') highCount++;
      if (r.risk.level === 'medium') mediumCount++;
    }
    if (highCount > 0) maxRiskLevel = 'high';
    else if (mediumCount > 0) maxRiskLevel = 'medium';

    return {
      sentences: results,
      overall: { level: maxRiskLevel, totalScore, highCount, mediumCount, sentenceCount: results.length },
    };
  }

  // ═══════════════════════════════════════════════════════════
  // §11  DOM MANIPULATION — BANNER, HIGHLIGHTS, TOOLTIPS
  // ═══════════════════════════════════════════════════════════

  function createBanner(overallRisk) {
    const existing = document.querySelector('.phishlens-banner');
    if (existing) existing.remove();

    const banner = document.createElement('div');
    banner.className = 'phishlens-banner';

    let iconEmoji, bannerClass, title, badgeText;
    switch (overallRisk.level) {
      case 'high':
        iconEmoji = '🚨'; bannerClass = 'phishlens-banner-danger';
        title = `PhishLens detected ${overallRisk.highCount} high-risk sentence${overallRisk.highCount > 1 ? 's' : ''}. This message may be a phishing attempt.`;
        badgeText = 'High Risk'; break;
      case 'medium':
        iconEmoji = '⚠️'; bannerClass = 'phishlens-banner-suspicious';
        title = `PhishLens found ${overallRisk.mediumCount} suspicious sentence${overallRisk.mediumCount > 1 ? 's' : ''}. Review this message carefully.`;
        badgeText = 'Suspicious'; break;
      default:
        iconEmoji = '✅'; bannerClass = 'phishlens-banner-safe';
        title = 'PhishLens: No phishing indicators detected. This message appears safe.';
        badgeText = 'Safe';
    }

    banner.classList.add(bannerClass);
    banner.innerHTML = `
      <span class="phishlens-banner-icon">${iconEmoji}</span>
      <span class="phishlens-banner-text">${title}</span>
      <span class="phishlens-banner-badge">${badgeText}</span>
      <button class="phishlens-close" title="Dismiss">&times;</button>
    `;
    banner.querySelector('.phishlens-close').addEventListener('click', () => {
      banner.style.animation = 'phishlens-fadeout 0.2s ease forwards';
      setTimeout(() => banner.remove(), 200);
    });
    return banner;
  }

  function createLoader() {
    const loader = document.createElement('div');
    loader.className = 'phishlens-loader';
    loader.id = 'phishlens-loader';
    loader.innerHTML = `
      <div class="phishlens-spinner"></div>
      <span>PhishLens is scanning this message for phishing indicators…</span>
    `;
    return loader;
  }

  function removeLoader() {
    const loader = document.getElementById('phishlens-loader');
    if (loader) {
      loader.style.animation = 'phishlens-fadeout 0.2s ease forwards';
      setTimeout(() => loader.remove(), 200);
    }
  }

  function highlightSentences(containerEl, analysisResults) {
    const riskyResults = analysisResults.sentences.filter(
      (r) => r.risk.level === 'high' || r.risk.level === 'medium'
    );
    if (riskyResults.length === 0) return;

    const walker = document.createTreeWalker(containerEl, NodeFilter.SHOW_TEXT, null, false);
    const textNodes = [];
    let node;
    while ((node = walker.nextNode())) {
      if (node.textContent.trim().length > 0) textNodes.push(node);
    }

    for (const result of riskyResults) {
      const cleanSentence = result.sentence.replace(/\s+/g, ' ').trim();
      for (const textNode of textNodes) {
        const nodeText = textNode.textContent;
        const normalizedNode = nodeText.replace(/\s+/g, ' ');
        const searchKey = cleanSentence.substring(0, Math.min(40, cleanSentence.length));
        const matchIndex = normalizedNode.indexOf(searchKey);
        if (matchIndex === -1) continue;

        let origStart = 0;
        let normalizedPos = 0;
        for (let i = 0; i < nodeText.length && normalizedPos < matchIndex; i++) {
          if (nodeText[i] === ' ' && i > 0 && nodeText[i - 1] === ' ') continue;
          normalizedPos++; origStart = i + 1;
        }

        let sentenceEndInNode = nodeText.indexOf('.', origStart);
        if (sentenceEndInNode === -1) sentenceEndInNode = nodeText.indexOf('!', origStart);
        if (sentenceEndInNode === -1) sentenceEndInNode = nodeText.indexOf('?', origStart);
        if (sentenceEndInNode === -1) sentenceEndInNode = nodeText.length;
        else sentenceEndInNode += 1;

        const matchedText = nodeText.substring(origStart, sentenceEndInNode);
        if (matchedText.trim().length < 5) continue;

        const highlightSpan = document.createElement('span');
        highlightSpan.className = `phishlens-highlight phishlens-highlight-${result.risk.level}`;

        const tooltip = document.createElement('div');
        tooltip.className = 'phishlens-tooltip';
        const headerClass = result.risk.level === 'high' ? 'phishlens-tooltip-header-high' : 'phishlens-tooltip-header-medium';
        const riskIcon = result.risk.level === 'high' ? '🚨' : '⚠️';
        const riskLabel = result.risk.level === 'high' ? 'High Risk' : 'Medium Risk';
        let signalTags = result.risk.activeSignals
          .map((s) => `<span class="phishlens-tooltip-signal">${formatSignalName(s)}</span>`).join('');

        tooltip.innerHTML = `
          <div class="phishlens-tooltip-header ${headerClass}">${riskIcon} ${riskLabel} · Score ${result.risk.score}</div>
          <div class="phishlens-tooltip-body">${result.explanation}</div>
          <div class="phishlens-tooltip-signals">${signalTags}</div>
        `;

        const inlineExplanation = document.createElement('div');
        inlineExplanation.className = `phishlens-inline-explanation phishlens-inline-explanation-${result.risk.level}`;
        let inlineSignalTags = result.risk.activeSignals
          .map((s) => `<span class="phishlens-inline-signal">${formatSignalName(s)}</span>`).join('');

        inlineExplanation.innerHTML = `
          <div class="phishlens-inline-header">
            <span class="phishlens-inline-icon">${riskIcon}</span>
            <span class="phishlens-inline-label">${riskLabel}</span>
            <span class="phishlens-inline-score">Score ${result.risk.score}</span>
          </div>
          <div class="phishlens-inline-text">${result.explanation}</div>
          <div class="phishlens-inline-signals">${inlineSignalTags}</div>
        `;

        const before = document.createTextNode(nodeText.substring(0, origStart));
        const highlighted = document.createTextNode(matchedText);
        const after = document.createTextNode(nodeText.substring(sentenceEndInNode));

        highlightSpan.appendChild(highlighted);
        highlightSpan.appendChild(tooltip);

        const parent = textNode.parentNode;
        parent.insertBefore(before, textNode);
        parent.insertBefore(highlightSpan, textNode);
        parent.insertBefore(inlineExplanation, textNode);
        parent.insertBefore(after, textNode);
        parent.removeChild(textNode);
        break;
      }
    }
  }

  function formatSignalName(signal) {
    const names = {
      ai_detected: '🤖 AI Model', urgency: '⏰ Urgency', fear: '😰 Fear',
      suspicious_url: '🔗 Bad URL', authority_mismatch: '👤 Authority', authority_claim: '👤 Authority',
    };
    return names[signal] || signal;
  }

  // ═══════════════════════════════════════════════════════════
  // §12  SIDE PANEL
  // ═══════════════════════════════════════════════════════════

  let _panelEl = null;
  let _toggleEl = null;
  let _panelOpen = false;

  function getRiskHSL(normalizedScore) {
    const hue = Math.round(120 - normalizedScore * 120);
    return `hsl(${hue}, 85%, 55%)`;
  }

  function createToggleButton() {
    if (_toggleEl) return _toggleEl;
    _toggleEl = document.createElement('button');
    _toggleEl.className = 'phishlens-panel-toggle';
    _toggleEl.id = 'phishlens-panel-toggle';
    _toggleEl.innerHTML = '🛡️';
    _toggleEl.title = 'Open PhishLens Panel';
    _toggleEl.addEventListener('click', () => togglePanel());
    document.body.appendChild(_toggleEl);
    return _toggleEl;
  }

  function togglePanel() {
    if (!_panelEl) return;
    _panelOpen = !_panelOpen;
    if (_panelOpen) { _panelEl.classList.add('phishlens-panel-open'); if (_toggleEl) _toggleEl.style.right = '370px'; }
    else { _panelEl.classList.remove('phishlens-panel-open'); if (_toggleEl) _toggleEl.style.right = '0'; }
  }

  function createSidePanel() {
    if (_panelEl) return _panelEl;
    _panelEl = document.createElement('div');
    _panelEl.className = 'phishlens-panel';
    _panelEl.id = 'phishlens-panel';

    const platformLabel = currentPlatform ? currentPlatform.name : 'email';
    _panelEl.innerHTML = `
      <div class="phishlens-panel-header">
        <div class="phishlens-panel-logo">
          <span class="phishlens-panel-logo-icon">🛡️</span>
          <span>PhishLens</span>
        </div>
        <button class="phishlens-panel-close" id="phishlens-panel-close-btn" title="Close panel">&times;</button>
      </div>
      <div class="phishlens-panel-body" id="phishlens-panel-body">
        <div class="phishlens-panel-empty">
          <div class="phishlens-panel-empty-icon">📧</div>
          <div class="phishlens-panel-empty-text">
            Open a message on ${platformLabel} to see<br>the phishing analysis results
          </div>
        </div>
      </div>
      <div class="phishlens-panel-footer">
        🔒 All analysis runs locally · No data leaves your browser
      </div>
    `;
    _panelEl.querySelector('#phishlens-panel-close-btn').addEventListener('click', () => togglePanel());
    document.body.appendChild(_panelEl);
    createToggleButton();
    return _panelEl;
  }

  function buildGaugeHTML(score, maxScore, level) {
    const r = 75;
    const circumference = Math.PI * r;
    const cappedScore = Math.min(score, maxScore);
    const normalized = cappedScore / maxScore;
    const fillLength = circumference * normalized;
    const dashOffset = circumference - fillLength;
    const color = getRiskHSL(normalized);
    const levelText = level === 'low' ? 'Safe' : level === 'medium' ? 'Suspicious' : 'High Risk';

    return `
      <div class="phishlens-gauge-container">
        <div class="phishlens-gauge">
          <svg viewBox="0 0 180 110">
            <path class="phishlens-gauge-bg" d="M 15,90 A ${r},${r} 0 0,1 165,90" />
            <path class="phishlens-gauge-fill" d="M 15,90 A ${r},${r} 0 0,1 165,90"
              stroke="${color}" stroke-dasharray="${circumference}" stroke-dashoffset="${dashOffset}"
              style="animation: phishlens-gauge-appear 1.2s cubic-bezier(0.4, 0, 0.2, 1) forwards;" />
          </svg>
          <div class="phishlens-gauge-label">
            <div class="phishlens-gauge-score" style="color: ${color}">${score}</div>
            <div class="phishlens-gauge-max">/ ${maxScore}</div>
          </div>
        </div>
        <span class="phishlens-gauge-level phishlens-gauge-level-${level}">${levelText}</span>
      </div>
    `;
  }

  function buildStatsHTML(overall) {
    return `
      <div class="phishlens-stats-row">
        <div class="phishlens-stat-card"><div class="phishlens-stat-value" style="color: var(--pl-text-light)">${overall.sentenceCount}</div><div class="phishlens-stat-label">Sentences</div></div>
        <div class="phishlens-stat-card"><div class="phishlens-stat-value" style="color: var(--pl-red)">${overall.highCount}</div><div class="phishlens-stat-label">High Risk</div></div>
        <div class="phishlens-stat-card"><div class="phishlens-stat-value" style="color: var(--pl-yellow)">${overall.mediumCount}</div><div class="phishlens-stat-label">Suspicious</div></div>
      </div>
    `;
  }

  function buildSignalsHTML(results) {
    const signalCounts = {};
    const signalMeta = {
      ai_detected: { icon: '🤖', name: 'AI Model Detection', detail: 'Neural network phishing pattern match' },
      urgency: { icon: '⏰', name: 'Urgency Pressure', detail: 'Time-pressure language detected' },
      fear: { icon: '😰', name: 'Fear / Threats', detail: 'Threatening or fear-inducing language' },
      suspicious_url: { icon: '🔗', name: 'Suspicious URLs', detail: 'Shorteners, bad TLDs, or domain mismatch' },
      authority_mismatch: { icon: '👤', name: 'Authority Mismatch', detail: 'Claims authority with mismatched links' },
      authority_claim: { icon: '👔', name: 'Authority Claims', detail: 'Claims to be from authority figure' },
    };

    for (const r of results.sentences) { for (const sig of r.risk.activeSignals) { signalCounts[sig] = (signalCounts[sig] || 0) + 1; } }

    let html = '<div class="phishlens-section-title">Signal Breakdown</div><div class="phishlens-signals-list">';
    const allSignals = ['ai_detected', 'urgency', 'fear', 'suspicious_url', 'authority_mismatch', 'authority_claim'];
    for (const sig of allSignals) {
      const count = signalCounts[sig] || 0;
      const meta = signalMeta[sig] || { icon: '❓', name: sig, detail: '' };
      const isActive = count > 0;
      const badgeClass = isActive ? 'phishlens-signal-badge-active' : 'phishlens-signal-badge-inactive';
      html += `<div class="phishlens-signal-row"><span class="phishlens-signal-icon">${meta.icon}</span><div class="phishlens-signal-info"><div class="phishlens-signal-name">${meta.name}</div><div class="phishlens-signal-detail">${meta.detail}</div></div><span class="phishlens-signal-badge ${badgeClass}">${isActive ? count : '—'}</span></div>`;
    }
    html += '</div>';
    return html;
  }

  function escapeHTML(str) { const div = document.createElement('div'); div.textContent = str; return div.innerHTML; }

  function buildSentencesHTML(results) {
    const risky = results.sentences.filter((r) => r.risk.level !== 'low');
    if (risky.length === 0) {
      return '<div class="phishlens-section-title">Flagged Sentences</div><div style="text-align: center; padding: 16px; color: var(--pl-text-dim); font-size: 12px;">✅ No sentences flagged — this message looks clean.</div>';
    }
    let html = `<div class="phishlens-section-title">Flagged Sentences (${risky.length})</div><div class="phishlens-sentence-list">`;
    for (const r of risky) {
      const levelLabel = r.risk.level === 'high' ? '🚨 HIGH' : '⚠️ MED';
      const truncated = r.sentence.length > 120 ? r.sentence.substring(0, 120) + '…' : r.sentence;
      html += `<div class="phishlens-sentence-card phishlens-sentence-card-${r.risk.level}"><div class="phishlens-sentence-text">${escapeHTML(truncated)}</div><div class="phishlens-sentence-meta"><span class="phishlens-sentence-score phishlens-sentence-score-${r.risk.level}">${levelLabel} · Score ${r.risk.score}</span>${r.explanation ? `<span class="phishlens-sentence-explanation">${escapeHTML(r.explanation.substring(0, 80))}</span>` : ''}</div></div>`;
    }
    html += '</div>';
    return html;
  }

  function updateSidePanel(results) {
    createSidePanel();
    const body = document.getElementById('phishlens-panel-body');
    if (!body) return;
    const maxPossibleScore = 12;
    const displayScore = Math.min(results.overall.totalScore, maxPossibleScore);
    body.innerHTML = buildGaugeHTML(displayScore, maxPossibleScore, results.overall.level) + buildStatsHTML(results.overall) + buildSignalsHTML(results) + buildSentencesHTML(results);

    if (_toggleEl) {
      _toggleEl.classList.remove('phishlens-toggle-danger', 'phishlens-toggle-warning', 'phishlens-toggle-safe');
      if (results.overall.level === 'high') { _toggleEl.classList.add('phishlens-toggle-danger'); _toggleEl.title = 'PhishLens: High Risk Detected!'; }
      else if (results.overall.level === 'medium') { _toggleEl.classList.add('phishlens-toggle-warning'); _toggleEl.title = 'PhishLens: Suspicious Content Found'; }
      else { _toggleEl.classList.add('phishlens-toggle-safe'); _toggleEl.title = 'PhishLens: Message Looks Safe'; }
    }
    if (results.overall.level === 'high' && !_panelOpen) togglePanel();
  }

  // ═══════════════════════════════════════════════════════════
  // §13  PLATFORM-SPECIFIC EXTRACTORS
  // ═══════════════════════════════════════════════════════════

  /**
   * Extract text from an element, removing quotes and PhishLens elements.
   */
  function extractCleanText(el) {
    if (!el) return '';
    const clone = el.cloneNode(true);

    // Remove quote selectors for this platform
    if (currentPlatform.quoteSelectors) {
      for (const sel of currentPlatform.quoteSelectors) {
        try { clone.querySelectorAll(sel).forEach((q) => q.remove()); } catch (e) { /* ignore */ }
      }
    }

    // Remove PhishLens injected elements
    clone.querySelectorAll('.phishlens-tooltip, .phishlens-inline-explanation, .phishlens-banner, .phishlens-loader').forEach((el) => el.remove());
    clone.querySelectorAll('.phishlens-highlight').forEach((el) => {
      const parent = el.parentNode;
      while (el.firstChild) parent.insertBefore(el.firstChild, el);
      parent.removeChild(el);
    });

    let text = clone.innerText || clone.textContent || '';
    text = text.replace(/\r\n/g, '\n').replace(/\n{3,}/g, '\n\n').replace(/[\t ]+/g, ' ').trim();
    return text;
  }

  /**
   * Find the message body element(s) for the current platform.
   * Returns an array of { element, text } objects.
   */
  function findMessageBodies() {
    const bodies = [];

    for (const selector of currentPlatform.bodySelectors) {
      try {
        const elements = document.querySelectorAll(selector);
        for (const el of elements) {
          const text = extractCleanText(el);
          if (text.length > 20) {
            bodies.push({ element: el, text });
          }
        }
        if (bodies.length > 0) break;
      } catch (e) { /* ignore invalid selectors */ }
    }

    // For chat platforms (WhatsApp, Telegram), aggregate recent messages
    if (currentPlatform.type === 'chat' && bodies.length > 1) {
      // Combine the last N messages into one text block for analysis
      const recentMessages = bodies.slice(-20);
      const combinedText = recentMessages.map(b => b.text).join('\n');
      if (combinedText.length > 20) {
        // Use the parent container of the last message for banner insertion
        const lastEl = recentMessages[recentMessages.length - 1].element;
        return [{ element: lastEl, text: combinedText, isChat: true }];
      }
    }

    // For email platforms, take the last (most recently opened) body
    if (bodies.length > 0) {
      return [bodies[bodies.length - 1]];
    }

    return [];
  }

  // ═══════════════════════════════════════════════════════════
  // §14  MAIN PROCESSING & MUTATION OBSERVER
  // ═══════════════════════════════════════════════════════════

  let lastProcessedHash = null;
  let isProcessing = false;
  let _isModifyingDOM = false;
  let debounceTimer = null;
  let lastKnownURL = '';

  function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const chr = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + chr;
      hash |= 0;
    }
    return hash.toString();
  }

  async function processMessage(bodyInfo) {
    if (isProcessing || !isEnabled()) return;

    const { element, text } = bodyInfo;
    if (!text || text.length < 20) return;

    const contentHash = simpleHash(text);
    if (contentHash === lastProcessedHash) return;

    isProcessing = true;
    lastProcessedHash = contentHash;

    console.log(`[PhishLens] 📧 New message detected on ${currentPlatform.name}, starting analysis…`);
    console.log('[PhishLens] Text length:', text.length, 'characters');

    _isModifyingDOM = true;
    document.querySelectorAll('.phishlens-banner, .phishlens-loader, .phishlens-inline-explanation').forEach((el) => el.remove());
    document.querySelectorAll('.phishlens-highlight').forEach((el) => {
      const parent = el.parentNode;
      const textNode = document.createTextNode(el.textContent);
      parent.replaceChild(textNode, el);
      parent.normalize();
    });
    _isModifyingDOM = false;

    _isModifyingDOM = true;
    const loader = createLoader();
    const insertTarget = element.parentElement || element;
    insertTarget.insertBefore(loader, element);
    _isModifyingDOM = false;

    try {
      const startTime = performance.now();
      const results = await analyzeEmail(text);
      const elapsed = (performance.now() - startTime).toFixed(0);

      console.log(`[PhishLens] ✅ Analysis complete in ${elapsed}ms`);
      console.log(`[PhishLens] Overall: ${results.overall.level.toUpperCase()} (score: ${results.overall.totalScore})`);

      _isModifyingDOM = true;
      removeLoader();
      const banner = createBanner(results.overall);
      insertTarget.insertBefore(banner, element);
      highlightSentences(element, results);
      _isModifyingDOM = false;

      updateSidePanel(results);

      const riskyResults = results.sentences.filter((r) => r.risk.level !== 'low');
      if (riskyResults.length > 0) {
        console.group('[PhishLens] 🔍 Detailed Results');
        for (const r of riskyResults) {
          console.log(`  [${r.risk.level.toUpperCase()}] Score: ${r.risk.score} | "${r.sentence.substring(0, 80)}…"`);
        }
        console.groupEnd();
      }
    } catch (err) {
      console.error('[PhishLens] ❌ Analysis error:', err);
      _isModifyingDOM = true;
      removeLoader();
      _isModifyingDOM = false;
    } finally {
      isProcessing = false;
    }
  }

  function checkForMessages() {
    if (_isModifyingDOM || isProcessing || !isEnabled()) return;
    const bodies = findMessageBodies();
    if (bodies.length === 0) return;
    processMessage(bodies[0]);
  }

  function debouncedCheck() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(checkForMessages, CONFIG.DEBOUNCE_MS);
  }

  function initObserver() {
    const observer = new MutationObserver((mutations) => {
      if (_isModifyingDOM || isProcessing) return;

      let shouldCheck = false;
      for (const mutation of mutations) {
        if (mutation.target && mutation.target.className &&
          typeof mutation.target.className === 'string' &&
          mutation.target.className.includes('phishlens-')) continue;

        let isPhishLensNode = false;
        if (mutation.addedNodes.length > 0) {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE && node.className &&
              typeof node.className === 'string' && node.className.includes('phishlens-')) {
              isPhishLensNode = true; break;
            }
          }
        }
        if (isPhishLensNode) continue;

        if (mutation.addedNodes.length > 0) {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE) {
              // Check if any platform body selector matches
              for (const sel of currentPlatform.bodySelectors) {
                try {
                  if (node.matches?.(sel) || node.querySelector?.(sel) || node.closest?.(sel)) {
                    shouldCheck = true; break;
                  }
                } catch (e) { /* ignore */ }
              }
              if (shouldCheck) break;

              // Gmail-specific containers
              if (currentPlatform.key === 'gmail' && node.classList &&
                (node.classList.contains('nH') || node.classList.contains('adn') || node.classList.contains('a3s'))) {
                shouldCheck = true; break;
              }
            }
          }
        }

        if (mutation.type === 'characterData' || mutation.type === 'childList') {
          const target = mutation.target;
          for (const sel of currentPlatform.bodySelectors) {
            try {
              if (target && target.nodeType === Node.ELEMENT_NODE && target.closest && target.closest(sel)) { shouldCheck = true; break; }
              if (target && target.parentElement && target.parentElement.closest && target.parentElement.closest(sel)) { shouldCheck = true; break; }
            } catch (e) { /* ignore */ }
          }
        }
        if (shouldCheck) break;
      }

      if (shouldCheck) debouncedCheck();
    });

    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    console.log(`[PhishLens] 👁️ MutationObserver active on ${currentPlatform.name} — watching for messages`);

    setTimeout(checkForMessages, 1000);

    window.addEventListener('hashchange', () => {
      console.log('[PhishLens] 📍 URL changed (hashchange)');
      lastProcessedHash = null;
      setTimeout(debouncedCheck, 500);
    });

    lastKnownURL = location.href;
    setInterval(() => {
      if (location.href !== lastKnownURL) {
        console.log('[PhishLens] 📍 URL changed (poll detected)');
        lastKnownURL = location.href;
        lastProcessedHash = null;
        debouncedCheck();
      }
    }, 2000);

    // For chat platforms, check more frequently for new messages
    const pollInterval = currentPlatform.type === 'chat' ? 3000 : 5000;
    setInterval(() => {
      if (!isProcessing && isEnabled()) checkForMessages();
    }, pollInterval);
  }

  // ═══════════════════════════════════════════════════════════
  // §15  INITIALIZATION
  // ═══════════════════════════════════════════════════════════

  async function init() {
    // Load toggle state first
    await loadToggleState();

    if (!isEnabled()) {
      console.log(`[PhishLens] ⏸️ Extension disabled for ${currentPlatform.name}`);
      return;
    }

    const checkReady = setInterval(() => {
      let appReady = false;
      for (const sel of currentPlatform.readySelectors) {
        try {
          if (document.querySelector(sel)) { appReady = true; break; }
        } catch (e) { /* ignore */ }
      }

      if (appReady) {
        clearInterval(checkReady);
        console.log(`[PhishLens] 🚀 ${currentPlatform.name} detected — initializing PhishLens`);
        createSidePanel();
        initObserver();
      }
    }, 500);

    setTimeout(() => clearInterval(checkReady), 30000);
  }

  // Start!
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
