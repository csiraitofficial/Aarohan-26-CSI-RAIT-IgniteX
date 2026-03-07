/**
 * ============================================================
 * PhishLens — Content Script for Gmail Phishing Detection
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
 * All phishing detection — including AI inference via ONNX Runtime
 * Web and rule-based analysis — executes on-device within the
 * user's browser. Email content never leaves the machine.
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
    // ONNX inference threshold — sentences above this probability
    // are flagged as AI-detected phishing
    ONNX_THRESHOLD: 0.75,

    // Risk score thresholds
    RISK_LOW_MAX: 2,
    RISK_MEDIUM_MAX: 5,
    // 6+ → HIGH

    // Signal weights
    WEIGHT_ONNX: 3,
    WEIGHT_URGENCY: 2,
    WEIGHT_FEAR: 2,
    WEIGHT_SUSPICIOUS_URL: 3,
    WEIGHT_AUTHORITY: 2,

    // Gmail email body selector
    EMAIL_BODY_SELECTOR: '.a3s.aiL',

    // Debounce delay for MutationObserver (ms)
    DEBOUNCE_MS: 1200,

    // Maximum sentences to process per email
    MAX_SENTENCES: 50,

    // Minimum sentence length to bother analyzing
    MIN_SENTENCE_LENGTH: 15,

    // Concurrent inference batch size
    BATCH_SIZE: 5,
  };

  // ═══════════════════════════════════════════════════════════
  // §2  SENTENCE SPLITTER
  // ═══════════════════════════════════════════════════════════

  /**
   * Split email text into individual sentences.
   * Handles common abbreviations, URLs, and edge cases.
   */
  function splitSentences(text) {
    if (!text || typeof text !== 'string') return [];

    // Common abbreviations that shouldn't end sentences
    const abbrevs = /(?:Mr|Mrs|Ms|Dr|Prof|Jr|Sr|Inc|Ltd|Corp|Co|vs|etc|approx|dept|est|govt|i\.e|e\.g)\./gi;

    // Replace abbreviation dots with placeholder
    let processed = text.replace(abbrevs, (match) => match.replace(/\./g, '{{DOT}}'));

    // Replace URL dots with placeholder
    processed = processed.replace(/https?:\/\/\S+/gi, (match) => match.replace(/\./g, '{{DOT}}'));

    // Replace email dots with placeholder
    processed = processed.replace(/[\w.-]+@[\w.-]+/gi, (match) => match.replace(/\./g, '{{DOT}}'));

    // Split on sentence boundaries
    const raw = processed.split(/(?<=[.!?])\s+/);

    // Restore dots and clean up
    return raw
      .map((s) => s.replace(/\{\{DOT\}\}/g, '.').trim())
      .filter((s) => s.length > 5); // Ignore very short fragments
  }

  // ═══════════════════════════════════════════════════════════
  // §3  URL DETECTOR
  // ═══════════════════════════════════════════════════════════

  /**
   * Detect and analyze URLs in a sentence.
   * Returns { urls, hasShortener, hasSuspiciousTLD, hasDomainMismatch }
   */
  function analyzeURLs(sentence) {
    const result = {
      urls: [],
      hasShortener: false,
      hasSuspiciousTLD: false,
      hasDomainMismatch: false,
      brands: [],
    };

    // Extract URLs
    const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
    const matches = sentence.match(urlRegex) || [];
    result.urls = matches;

    if (matches.length === 0) return result;

    // URL shortener domains
    const shorteners = [
      'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
      'is.gd', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in',
      'rb.gy', 'cutt.ly', 'shorturl.at',
    ];

    // Suspicious TLDs
    const suspiciousTLDs = [
      '.xyz', '.click', '.top', '.tk', '.ml', '.ga', '.cf',
      '.gq', '.buzz', '.club', '.work', '.link', '.info',
      '.ru', '.cn', '.pw',
    ];

    // Known brand names to check for domain mismatch
    const knownBrands = [
      'paypal', 'apple', 'google', 'microsoft', 'amazon',
      'netflix', 'facebook', 'instagram', 'bank', 'chase',
      'wells fargo', 'citibank', 'hsbc',
    ];

    for (const url of matches) {
      let hostname = '';
      try {
        hostname = new URL(url).hostname.toLowerCase();
      } catch (e) {
        hostname = url.toLowerCase();
      }

      // Check shorteners
      if (shorteners.some((s) => hostname.includes(s))) {
        result.hasShortener = true;
      }

      // Check suspicious TLDs
      if (suspiciousTLDs.some((tld) => hostname.endsWith(tld))) {
        result.hasSuspiciousTLD = true;
      }

      // Check domain mismatch — brand mentioned in sentence but URL
      // doesn't match the brand's domain
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
  // §4  RULE-BASED ENGINE
  // ═══════════════════════════════════════════════════════════

  /**
   * Rule-based phishing signal detection.
   * Returns an object with boolean flags for each triggered rule.
   */

  // ── Urgency keywords ──
  const URGENCY_PATTERNS = [
    'urgent', 'immediately', 'act now', 'verify today',
    'account suspended', 'right away', 'as soon as possible',
    'within 24 hours', 'within 48 hours', 'expire', 'final warning',
    'last chance', 'time is running out', 'don\'t delay',
    'must respond', 'action required', 'respond immediately',
  ];

  // ── Fear keywords ──
  const FEAR_PATTERNS = [
    'blocked', 'legal action', 'violation', 'penalty',
    'unauthorized', 'compromised', 'hacked', 'stolen',
    'permanent deletion', 'terminated', 'restricted',
    'closed', 'frozen', 'disabled', 'suspicious activity',
    'security breach', 'identity theft', 'lawsuit',
  ];

  // ── Authority keywords ──
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
      urgency: false,
      fear: false,
      authority: false,
      suspiciousURL: false,
      urlDetails: null,
      matchedUrgency: [],
      matchedFear: [],
      matchedAuthority: [],
    };

    // Urgency detection
    for (const pattern of URGENCY_PATTERNS) {
      if (lower.includes(pattern)) {
        signals.urgency = true;
        signals.matchedUrgency.push(pattern);
      }
    }

    // Fear detection
    for (const pattern of FEAR_PATTERNS) {
      if (lower.includes(pattern)) {
        signals.fear = true;
        signals.matchedFear.push(pattern);
      }
    }

    // Authority detection
    for (const pattern of AUTHORITY_PATTERNS) {
      if (lower.includes(pattern)) {
        signals.authority = true;
        signals.matchedAuthority.push(pattern);
      }
    }

    // URL analysis
    const urlAnalysis = analyzeURLs(sentence);
    if (urlAnalysis.hasShortener || urlAnalysis.hasSuspiciousTLD || urlAnalysis.hasDomainMismatch) {
      signals.suspiciousURL = true;
      signals.urlDetails = urlAnalysis;
    }

    // Authority mismatch — authority keyword + URL that doesn't match
    if (signals.authority && urlAnalysis.urls.length > 0 && urlAnalysis.hasDomainMismatch) {
      signals.authorityMismatch = true;
    }

    return signals;
  }

  // ═══════════════════════════════════════════════════════════
  // §5  ONNX MODEL INFERENCE
  // ═══════════════════════════════════════════════════════════

  /**
   * ONNX Runtime Web inference module.
   *
   * Loads a DistilBERT phishing classification model (model.onnx)
   * and runs real neural-network inference in the browser via
   * ONNX Runtime Web (WASM backend).
   *
   * Falls back to keyword-heuristic scoring if the model files
   * are not present (model.onnx or vocab.json missing).
   *
   * Returns: Promise<number> — phishing probability [0, 1]
   */

  let _onnxSession = null;
  let _ipOnnxSession = null;
  let _ipFeaturesDict = null;
  let _modelLoadAttempted = false;
  let _modelAvailable = false;
  let _ipModelAvailable = false;
  let _modelConfig = null;

  // Maximum token length for inference (shorter = faster)
  const INFERENCE_MAX_TOKENS = 128;

  /**
   * Resolve a chrome-extension:// URL for a web-accessible resource.
   */
  function getExtensionURL(path) {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL) {
      return chrome.runtime.getURL(path);
    }
    return path;
  }

  /**
   * Lazily load the ONNX model and tokenizer vocabulary.
   * Called once on the first inference request.
   */
  async function loadModel() {
    if (_modelLoadAttempted) return _modelAvailable;
    _modelLoadAttempted = true;

    try {
      console.log('[PhishLens] 🧠 Loading ONNX model…');

      // Configure ONNX Runtime WASM path
      if (typeof ort !== 'undefined') {
        ort.env.wasm.wasmPaths = getExtensionURL('lib/');
      } else {
        console.warn('[PhishLens] ⚠️ ONNX Runtime Web (ort) not found — using fallback');
        return false;
      }

      // Load tokenizer vocabulary
      const vocabUrl = getExtensionURL('model/vocab.json');
      await PhishLensTokenizer.loadVocab(vocabUrl);

      // Load model config (label mapping)
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

      // Load ONNX model
      const modelUrl = getExtensionURL('model/model.onnx');
      _onnxSession = await ort.InferenceSession.create(modelUrl, {
        executionProviders: ['wasm'],
        graphOptimizationLevel: 'all',
      });

      _modelAvailable = true;
      console.log('[PhishLens] ✅ ONNX model loaded successfully');
      console.log('[PhishLens] Input names:', _onnxSession.inputNames);
      console.log('[PhishLens] Output names:', _onnxSession.outputNames);

      // Load IP Risk ONNX model and features
      try {
        const ipModelUrl = getExtensionURL('model/ip_model.onnx');
        _ipOnnxSession = await ort.InferenceSession.create(ipModelUrl, {
          executionProviders: ['wasm'],
          graphOptimizationLevel: 'none',
        });

        const ipFeaturesUrl = getExtensionURL('model/ip_features.json');
        const ipFeatResp = await fetch(ipFeaturesUrl);
        if (ipFeatResp.ok) {
          _ipFeaturesDict = await ipFeatResp.json();
          _ipModelAvailable = true;
          console.log('[PhishLens] ✅ IP Risk ONNX model & features loaded');
        } else {
          console.warn('[PhishLens] ⚠️ Could not load IP features JSON');
        }
      } catch (err) {
        console.warn('[PhishLens] ⚠️ Could not load IP Risk ONNX model:', err.message);
      }

      return true;
    } catch (err) {
      console.warn('[PhishLens] ⚠️ Could not load ONNX model — falling back to heuristic:', err.message);
      _modelAvailable = false;
      return false;
    }
  }

  /**
   * Sigmoid activation function.
   */
  function sigmoid(x) {
    return 1 / (1 + Math.exp(-x));
  }

  /**
   * Softmax over an array of logits.
   */
  function softmax(logits) {
    const maxLogit = Math.max(...logits);
    const exps = logits.map((l) => Math.exp(l - maxLogit));
    const sumExps = exps.reduce((a, b) => a + b, 0);
    return exps.map((e) => e / sumExps);
  }

  /**
   * Run real ONNX inference on a sentence.
   * Returns phishing probability [0, 1].
   */
  async function runONNXModelInference(sentence) {
    // Tokenize
    const { inputIds, attentionMask } = PhishLensTokenizer.tokenize(sentence, INFERENCE_MAX_TOKENS);

    // Create tensors
    const inputIdsTensor = new ort.Tensor('int64', BigInt64Array.from(inputIds.map(BigInt)), [1, inputIds.length]);
    const attentionMaskTensor = new ort.Tensor('int64', BigInt64Array.from(attentionMask.map(BigInt)), [1, attentionMask.length]);

    // Build feeds object — match the model's expected input names
    const feeds = {};
    const inputNames = _onnxSession.inputNames;

    if (inputNames.includes('input_ids')) {
      feeds['input_ids'] = inputIdsTensor;
    } else {
      feeds[inputNames[0]] = inputIdsTensor;
    }

    if (inputNames.includes('attention_mask')) {
      feeds['attention_mask'] = attentionMaskTensor;
    } else if (inputNames.length > 1) {
      feeds[inputNames[1]] = attentionMaskTensor;
    }

    // Run inference
    const output = await _onnxSession.run(feeds);
    const outputName = _onnxSession.outputNames[0];
    const logits = Array.from(output[outputName].data);

    // Extract phishing probability
    let phishingProb = 0;

    if (logits.length === 1) {
      // Binary single-logit output
      phishingProb = sigmoid(Number(logits[0]));
    } else if (logits.length === 2) {
      // Two-class softmax output [safe, phishing]
      const probs = softmax(logits.map(Number));

      // Determine which index is "phishing" from config
      let phishingIdx = 1; // Default: index 1 = phishing
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
      // Multi-class — take max suspicious probability
      const probs = softmax(logits.map(Number));
      phishingProb = Math.max(...probs.slice(1)); // Assume index 0 = safe
    }

    return phishingProb;
  }

  // ── Fallback: Keyword heuristic (used when model unavailable) ──

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
      if (lower.includes(ngram)) {
        maxScore = Math.max(maxScore, weight);
        matchCount++;
      }
    }

    if (matchCount >= 3) maxScore = Math.min(1.0, maxScore + 0.1);
    if (matchCount >= 2) maxScore = Math.min(1.0, maxScore + 0.05);

    return maxScore;
  }

  /**
   * Main inference entry point.
   * Uses real ONNX model if available, falls back to keyword heuristic.
   */
  async function runONNXInference(sentence) {
    // Ensure model load has been attempted
    await loadModel();

    if (_modelAvailable && _onnxSession) {
      try {
        return await runONNXModelInference(sentence);
      } catch (err) {
        console.warn('[PhishLens] ONNX inference error, using fallback:', err.message);
        return runFallbackInference(sentence);
      }
    }

    return runFallbackInference(sentence);
  }

  // ═══════════════════════════════════════════════════════════
  // §5.5 IP ONNX MODEL INFERENCE
  // ═══════════════════════════════════════════════════════════

  function extractIPs(text) {
    const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
    const matches = text.match(ipRegex) || [];
    return [...new Set(matches.filter(ip => {
      return ip.split('.').every(p => parseInt(p, 10) <= 255);
    }))];
  }

  async function runIPInference(ip) {
    if (!_ipModelAvailable || !_ipOnnxSession || !_ipFeaturesDict) return { label: 'Unknown' };

    const features = _ipFeaturesDict[ip];
    if (!features) return { label: 'Unknown' };

    try {
      const tensor = new ort.Tensor('float32', Float32Array.from(features), [1, 15]);
      const feeds = {};
      feeds[_ipOnnxSession.inputNames[0]] = tensor;

      const output = await _ipOnnxSession.run(feeds);
      const labelTensor = output[_ipOnnxSession.outputNames[0]];
      
      let label = null;
      if (labelTensor.type === 'string' && labelTensor.data.length > 0) {
        label = labelTensor.data[0];
      } else if (labelTensor.type === 'int64' && labelTensor.data.length > 0) {
        // Fallback numerical mapping if needed
        const mapping = {0: 'Allow', 1: 'Monitor', 2: 'Restrict', 3: 'Block'};
        label = mapping[Number(labelTensor.data[0])] || 'Allow';
      }
      
      return { label: label || 'Allow' };
    } catch (err) {
      console.warn('[PhishLens] IP Inference Error:', err.message);
      return null;
    }
  }

  // ═══════════════════════════════════════════════════════════
  // §6  RISK SCORER
  // ═══════════════════════════════════════════════════════════

  /**
   * Combine signals into a total risk score and category.
   * Returns { score, level, signals }
   */
  function calculateRisk(onnxProbability, ruleSignals) {
    const activeSignals = [];

    // ── DistilBERT is the PRIMARY scorer ─────────────────────
    // Convert ONNX model probability [0,1] to a 0-100 base score.
    // This makes model confidence the dominant signal — not just a bonus.
    let modelScore = Math.round(onnxProbability * 100);

    // ── Rule bonuses (additive, max +12 total) ────────────────
    // These refine the model score when linguistic context is found.
    let ruleBonus = 0;

    if (onnxProbability >= CONFIG.ONNX_THRESHOLD) {
      activeSignals.push('ai_detected');
    }

    if (ruleSignals.urgency) {
      ruleBonus += CONFIG.WEIGHT_URGENCY;
      activeSignals.push('urgency');
    }

    if (ruleSignals.fear) {
      ruleBonus += CONFIG.WEIGHT_FEAR;
      activeSignals.push('fear');
    }

    if (ruleSignals.suspiciousURL) {
      ruleBonus += CONFIG.WEIGHT_SUSPICIOUS_URL;
      activeSignals.push('suspicious_url');
    }

    if (ruleSignals.authorityMismatch) {
      ruleBonus += CONFIG.WEIGHT_AUTHORITY;
      activeSignals.push('authority_mismatch');
    } else if (ruleSignals.authority) {
      ruleBonus += 1;
      activeSignals.push('authority_claim');
    }

    // Final score: model drives it, rules amplify it.
    // Normalise rule bonus (max 12) to percentage points (max 24 extra points).
    const rulePctBonus = Math.round((ruleBonus / 12) * 24);
    const finalScore = Math.min(100, modelScore + rulePctBonus);

    // Consistent thresholds for both email and webdomain
    let level = 'low';
    if (finalScore >= 70) level = 'high';
    else if (finalScore >= 40) level = 'medium';

    return { score: finalScore, level, activeSignals };
  }

  // ═══════════════════════════════════════════════════════════
  // §6.5 SENDER IP EXTRACTION
  // ═══════════════════════════════════════════════════════════

  /**
   * Attempt to find the sender's IP. In a privacy-first Client Side
   * Extension, we can only parse what is in the DOM. Gmail sometimes
   * leaks the sender IP in the "Show Original" or "mailed-by" sections,
   * but broadly, we will just treat the FIRST VALID IP we extract from
   * the email headers/body as the "Sender IP" for demonstration.
   */
  async function extractSenderIP(text, emailBodyEl) {
    // 1. First, check if there's a specific header container we can scrape
    if (emailBodyEl) {
      // Look for the legacy message ID which allows us to fetch the raw source
      const messageEl = emailBodyEl.closest('[data-legacy-message-id]');
      if (messageEl) {
         const messageId = messageEl.getAttribute('data-legacy-message-id');
         if (messageId) {
            try {
               // Fetch the raw "Show Original" email source in the background
               const url = window.location.origin + `/mail/u/0/?ui=2&ik=&view=om&th=${messageId}`;
               const response = await fetch(url);
               const rawText = await response.text();

               // Extract from standard "Received: from" or "X-Originating-IP" headers
               // This regex looks for IP addresses in brackets or specific headers typical of origins
               const originRegex = /(?:Received: from .*?\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]|X-Originating-IP: \[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]?)/i;
               const match = rawText.match(originRegex);
               if (match) {
                  return match[1] || match[2];
               }
            } catch (e) {
               console.warn('[PhishLens] Failed to fetch raw email source:', e.message);
            }
         }
      }

      // Fallback: Check obvious visible headers
      const container = emailBodyEl.closest('.h7');
      if (container) {
        const details = container.innerText || '';
        const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
        const matches = details.match(ipRegex);
        if (matches && matches.length > 0) {
           return matches[0];
        }
      }
    }

    // 2. Fallback to the first IP found in the text
    const ips = extractIPs(text);
    if (ips.length > 0) return ips[0];

    return "Not Detected";
  }

  // ═══════════════════════════════════════════════════════════
  // §7  EXPLANATION GENERATOR
  // ═══════════════════════════════════════════════════════════

  /**
   * Generate human-readable explanation from triggered signals.
   */
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
      if (details.hasShortener) {
        explanations.push('Contains a URL shortener that obscures the real destination.');
      }
      if (details.hasSuspiciousTLD) {
        explanations.push('Links to a domain with a suspicious TLD commonly used in phishing.');
      }
      if (details.hasDomainMismatch) {
        explanations.push('The URL domain doesn\'t match the brand mentioned in the text.');
      }
    }

    if (risk.activeSignals.includes('authority_mismatch')) {
      explanations.push('Claims authority ("' + ruleSignals.matchedAuthority[0] + '") but the linked domain doesn\'t match.');
    } else if (risk.activeSignals.includes('authority_claim')) {
      explanations.push('Claims to be from an authority figure ("' + ruleSignals.matchedAuthority[0] + '").');
    }

    if (explanations.length === 0) {
      if (risk.level === 'medium') {
        explanations.push('This sentence shows some characteristics of phishing content.');
      } else if (risk.level === 'high') {
        explanations.push('Multiple phishing indicators detected in this sentence.');
      }
    }

    return explanations.join(' ');
  }

  // ═══════════════════════════════════════════════════════════
  // §7.5 FEATURE ATTRIBUTION (SHAP/LIME approximation)
  // ═══════════════════════════════════════════════════════════

  const _shapCache = new Map();

  const shapExplainer = {
    async explain(sentence, baseScore) {
      if (_shapCache.has(sentence)) return _shapCache.get(sentence);

      const words = sentence.split(/\s+/);
      const chunkSize = Math.max(1, Math.ceil(words.length / 8));
      const chunks = [];
      for (let i = 0; i < words.length; i += chunkSize) {
        chunks.push(words.slice(i, i + chunkSize).join(' '));
      }

      const shapValues = [];
      for (let i = 0; i < chunks.length; i++) {
        const maskedSentence = chunks.map((c, idx) => idx === i ? "" : c).join(" ").replace(/\s+/g, ' ').trim();
        let maskedScore = runFallbackInference(maskedSentence);
        if (_modelAvailable && _onnxSession) {
          try { maskedScore = await runONNXModelInference(maskedSentence); } catch (e) { }
        }

        let contribution = baseScore - maskedScore;
        shapValues.push({
          original: chunks[i],
          contribution: contribution
        });
      }

      _shapCache.set(sentence, shapValues);
      return shapValues;
    }
  };

  async function explainWithSHAP(sentence, baseModelProb) {
    if (baseModelProb < 0.3) return []; // Only run SHAP logic on highly suspicious sentences

    const shapValues = await shapExplainer.explain(sentence, baseModelProb);
    const explanations = [];

    for (const token of shapValues) {
      if (token.contribution > 0.10) {
        let type = "phishing-indicator";
        let explanationText = "Neural vector strongly matches phishing patterns";

        if (/(urgent|action|required|immediately|suspend|verify)/i.test(token.original)) {
          explanationText = "Urgency/Fear-inducing threat common in scams";
        } else if (/(account|login|password|update|payment)/i.test(token.original)) {
          explanationText = "High-risk credential harvesting terminology";
        } else if (/(win|prize|lottery|free|reward)/i.test(token.original)) {
          explanationText = "Common social engineering hook";
        }

        explanations.push({
          phrase: token.original,
          contribution: token.contribution,
          type: type,
          explanation: explanationText
        });
      }
    }
    return explanations.sort((a, b) => b.contribution - a.contribution);
  }

  // ═══════════════════════════════════════════════════════════
  // §8  ANALYSIS PIPELINE
  // ═══════════════════════════════════════════════════════════

  /**
   * Run the full analysis pipeline on a single sentence.
   */
  async function analyzeSentence(sentence) {
    // 1. ONNX inference
    const onnxProb = await runONNXInference(sentence);

    // 2. Rule-based detection
    const ruleSignals = detectRules(sentence);

    // 3. Risk scoring
    const risk = calculateRisk(onnxProb, ruleSignals);

    // 4. Explanation
    const explanation = generateExplanation(risk, ruleSignals, onnxProb);

    // 5. SHAP attribution
    let shapPhrases = [];
    if (risk.level !== 'low') {
      shapPhrases = await explainWithSHAP(sentence, onnxProb);
    }

    return {
      sentence,
      onnxProbability: onnxProb,
      ruleSignals,
      risk,
      explanation,
      shapPhrases,
    };
  }

  /**
   * Analyze all sentences from an email body.
   */
  async function analyzeEmail(text, emailBodyEl = null) {
    // --- IP Extraction and Analysis ---
    const extractedIPs = extractIPs(text);
    const senderIP = await extractSenderIP(text, emailBodyEl);

    const ipThreats = [];
    let hasHighRiskIP = false;
    let hasMediumRiskIP = false;
    let senderIPThreat = null;

    for (const ip of extractedIPs) {
      const res = await runIPInference(ip);
      if (res && res.label !== 'Allow' && res.label !== 'Unknown') {
        const threatObj = { ip: ip, label: res.label, isSender: (ip === senderIP) };
        ipThreats.push(threatObj);
        
        if (ip === senderIP) {
          senderIPThreat = threatObj;
        }

        if (res.label === 'Block' || res.label === 'Restrict') hasHighRiskIP = true;
        if (res.label === 'Monitor') hasMediumRiskIP = true;
      }
    }

    // Even if sender IP is 'Allow' or 'Unknown', we still want to log it for the UI
    if (senderIP && !senderIPThreat) {
       if (senderIP === "Not Detected") {
          senderIPThreat = { ip: senderIP, label: 'Unknown', isSender: true };
       } else {
          const res = await runIPInference(senderIP);
          senderIPThreat = { ip: senderIP, label: (res ? res.label : 'Unknown'), isSender: true };
       }
    }

    const sentences = splitSentences(text);
    // Filter out very short sentences that won't have meaningful signals
    const filtered = sentences
      .filter((s) => s.length >= CONFIG.MIN_SENTENCE_LENGTH)
      .slice(0, CONFIG.MAX_SENTENCES);

    // --- Phase 1: Fast rule-based pre-scan (synchronous, instant) ---
    // Only run expensive ONNX inference on sentences that have at least
    // one rule-based signal OR look suspicious. Skip clearly safe ones.
    const preScan = filtered.map((sentence) => ({
      sentence,
      rules: detectRules(sentence),
    }));

    const results = [];

    // --- Phase 2: Batch process with concurrency ---
    for (let i = 0; i < preScan.length; i += CONFIG.BATCH_SIZE) {
      const batch = preScan.slice(i, i + CONFIG.BATCH_SIZE);
      const batchResults = await Promise.all(
        batch.map(async ({ sentence, rules }) => {
          // Skip ONNX for sentences with zero rule signals to save time
          const hasAnySignal = rules.urgency || rules.fear || rules.suspiciousURL || rules.authority;
          let onnxProb = 0;
          if (hasAnySignal) {
            onnxProb = await runONNXInference(sentence);
          } else {
            // Light ONNX check only — use fallback heuristic (instant)
            onnxProb = runFallbackInference(sentence);
          }

          const risk = calculateRisk(onnxProb, rules);
          const explanation = generateExplanation(risk, rules, onnxProb);

          let shapPhrases = [];
          if (risk.level !== 'low') {
            shapPhrases = await explainWithSHAP(sentence, onnxProb);
          }

          return { sentence, onnxProbability: onnxProb, ruleSignals: rules, risk, explanation, shapPhrases };
        })
      );
      results.push(...batchResults);
    }

    // Compute overall risk
    let maxRiskLevel = 'low';
    let totalScore = 0;
    let highCount = 0;
    let mediumCount = 0;

    for (const r of results) {
      totalScore += r.risk.score;
      if (r.risk.level === 'high') highCount++;
      if (r.risk.level === 'medium') mediumCount++;
    }

    // Add IP Threat Contributions
    if (hasHighRiskIP) {
        highCount++;
        totalScore += 80;
    }
    if (hasMediumRiskIP) {
        mediumCount++;
        totalScore += 40;
    }

    if (highCount > 0) maxRiskLevel = 'high';
    else if (mediumCount > 0) maxRiskLevel = 'medium';

    return {
      sentences: results,
      ipThreats: ipThreats,
      senderIPThreat: senderIPThreat,
      overall: {
        level: maxRiskLevel,
        totalScore,
        highCount,
        mediumCount,
        sentenceCount: results.length,
      },
    };
  }

  // ═══════════════════════════════════════════════════════════
  // §9  DOM MANIPULATION — BANNER, HIGHLIGHTS, TOOLTIPS
  // ═══════════════════════════════════════════════════════════

  /**
   * Create and inject the risk banner above the email.
   */
  function createBanner(overallRisk) {
    // Remove existing banner
    const existing = document.querySelector('.phishlens-banner');
    if (existing) existing.remove();

    const banner = document.createElement('div');
    banner.className = 'phishlens-banner';

    let iconEmoji, bannerClass, title, badgeText;

    switch (overallRisk.level) {
      case 'high':
        iconEmoji = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
        bannerClass = 'phishlens-banner-danger';
        title = `Aegis AI: ${overallRisk.highCount} Critical threat vectors isolated. Navigation hazard.`;
        badgeText = 'CRITICAL';
        break;
      case 'medium':
        iconEmoji = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
        bannerClass = 'phishlens-banner-suspicious';
        title = `Aegis AI: ${overallRisk.mediumCount} Suspicious patterns detected. Proceed with caution.`;
        badgeText = 'WARNING';
        break;
      default:
        iconEmoji = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>';
        bannerClass = 'phishlens-banner-safe';
        title = 'Aegis AI: No significant threat vectors detected.';
        badgeText = 'SECURE';
    }

    banner.classList.add(bannerClass);
    banner.innerHTML = `
      <span class="phishlens-banner-icon">${iconEmoji}</span>
      <span class="phishlens-banner-text">${title}</span>
      <span class="phishlens-banner-badge">${badgeText}</span>
      <button class="phishlens-close" title="Dismiss">&times;</button>
    `;

    // Close button handler
    banner.querySelector('.phishlens-close').addEventListener('click', () => {
      banner.style.animation = 'phishlens-fadeout 0.2s ease forwards';
      setTimeout(() => banner.remove(), 200);
    });

    return banner;
  }

  /**
   * Create the scanning loader element.
   */
  function createLoader() {
    const loader = document.createElement('div');
    loader.className = 'phishlens-loader';
    loader.id = 'phishlens-loader';
    loader.innerHTML = `
      <div class="phishlens-spinner"></div>
      <span>PhishLens is scanning this email for phishing indicators…</span>
    `;
    return loader;
  }

  /**
   * Remove the loader.
   */
  function removeLoader() {
    const loader = document.getElementById('phishlens-loader');
    if (loader) {
      loader.style.animation = 'phishlens-fadeout 0.2s ease forwards';
      setTimeout(() => loader.remove(), 200);
    }
  }

  /**
   * Highlight risky sentences within the email body element.
   * This wraps matched text in <span> elements with tooltip.
   */
  function highlightSentences(emailBodyEl, analysisResults) {
    const riskyResults = analysisResults.sentences.filter(
      (r) => r.risk.level === 'high' || r.risk.level === 'medium'
    );

    if (riskyResults.length === 0) return;

    // Walk through text nodes in the email body
    const walker = document.createTreeWalker(
      emailBodyEl,
      NodeFilter.SHOW_TEXT,
      null,
      false
    );

    const textNodes = [];
    let node;
    while ((node = walker.nextNode())) {
      if (node.textContent.trim().length > 0) {
        textNodes.push(node);
      }
    }

    for (const result of riskyResults) {
      const sentenceText = result.sentence;
      // Clean the sentence for matching (remove extra spaces)
      const cleanSentence = sentenceText.replace(/\s+/g, ' ').trim();

      for (const textNode of textNodes) {
        const nodeText = textNode.textContent;
        const normalizedNode = nodeText.replace(/\s+/g, ' ');

        // Find a reasonable match (first 40 chars of the sentence)
        const searchKey = cleanSentence.substring(0, Math.min(40, cleanSentence.length));

        const matchIndex = normalizedNode.indexOf(searchKey);
        if (matchIndex === -1) continue;

        // Find the real match boundaries in the original text
        // Map from normalized position back to original position
        let origStart = 0;
        let normalizedPos = 0;
        for (let i = 0; i < nodeText.length && normalizedPos < matchIndex; i++) {
          if (nodeText[i] === ' ' && i > 0 && nodeText[i - 1] === ' ') continue;
          normalizedPos++;
          origStart = i + 1;
        }

        // Find the end of the sentence in the text node
        let sentenceEndInNode = nodeText.indexOf('.', origStart);
        if (sentenceEndInNode === -1) sentenceEndInNode = nodeText.indexOf('!', origStart);
        if (sentenceEndInNode === -1) sentenceEndInNode = nodeText.indexOf('?', origStart);
        if (sentenceEndInNode === -1) sentenceEndInNode = nodeText.length;
        else sentenceEndInNode += 1; // Include the punctuation

        const matchedText = nodeText.substring(origStart, sentenceEndInNode);
        if (matchedText.trim().length < 5) continue;

        // Create the highlight wrapper (no tooltip — reason shown inline)
        const highlightSpan = document.createElement('span');
        highlightSpan.className = `phishlens-highlight phishlens-highlight-${result.risk.level}`;

        const riskIsHigh = result.risk.level === 'high';
        const riskLabel = riskIsHigh ? 'CRITICAL VECTOR' : 'SUSPICIOUS PATTERN';
        const riskColor = riskIsHigh ? 'var(--pl-accent-danger)' : 'var(--pl-accent-warning)';
        const riskBorderColor = riskIsHigh ? 'rgba(239,68,68,0.3)' : 'rgba(245,158,11,0.3)';
        const riskBg = riskIsHigh ? 'rgba(239,68,68,0.08)' : 'rgba(245,158,11,0.08)';
        const shieldIcon = riskIsHigh
          ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${riskColor}" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`
          : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${riskColor}" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;

        const pct = Math.min(100, Math.round(result.risk.score));

        // Build signal chip HTML
        const signalChips = result.risk.activeSignals.map(s => {
          const label = formatSignalName(s).replace(/<[^>]+>/g, '').trim();
          return `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);font-size:10px;font-family:monospace;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;">${label}</span>`;
        }).join('');

        // Create inline reason card — always visible, below the sentence
        const reasonCard = document.createElement('div');
        reasonCard.className = 'phishlens-inline-explanation phishlens-inline-explanation-' + result.risk.level;
        reasonCard.style.cssText = `
          display: flex;
          flex-direction: column;
          gap: 8px;
          margin: 8px 0 14px 0;
          padding: 14px 16px;
          border-radius: 10px;
          border-left: 3px solid ${riskColor};
          background: ${riskBg};
          border-top: 1px solid ${riskBorderColor};
          border-right: 1px solid ${riskBorderColor};
          border-bottom: 1px solid ${riskBorderColor};
          font-family: system-ui, sans-serif;
          animation: phishlens-fadein 0.3s ease;
        `;
        reasonCard.innerHTML = `
          <div style="display:flex;align-items:center;gap:8px;">
            ${shieldIcon}
            <span style="font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:1.5px;color:${riskColor};">${riskLabel}</span>
            <span style="margin-left:auto;font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;background:${riskBg};border:1px solid ${riskBorderColor};color:${riskColor};font-family:monospace;">${pct}% match</span>
          </div>
          <div style="font-size:12px;color:#94a3b8;line-height:1.6;">${result.explanation || 'Suspicious phishing indicators detected in this sentence.'}</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:2px;">${signalChips}</div>
        `;

        // Split the text node
        const before = document.createTextNode(nodeText.substring(0, origStart));
        const highlighted = document.createTextNode(matchedText);
        const after = document.createTextNode(nodeText.substring(sentenceEndInNode));

        highlightSpan.appendChild(highlighted);

        // Natively allocated hover bubble (tooltip) with simplified explanation
        const tooltip = document.createElement('div');
        tooltip.className = 'phishlens-tooltip';

        let simpleExplanation = result.explanation || 'Suspicious phrasing detected.';
        if (result.shapPhrases && result.shapPhrases.length > 0) {
          const mainPhrase = result.shapPhrases[0];
          simpleExplanation = `The phrase <b>"${mainPhrase.phrase}"</b> is highly suspicious. ${mainPhrase.explanation}.`;
        }

        tooltip.innerHTML = `
          <div class="phishlens-tooltip-header phishlens-tooltip-header-${result.risk.level}">
            ${shieldIcon}
            AI Threat Assessment
          </div>
          <div class="phishlens-tooltip-body">
            ${simpleExplanation}
          </div>
        `;
        highlightSpan.appendChild(tooltip);

        const parent = textNode.parentNode;
        parent.insertBefore(before, textNode);
        parent.insertBefore(highlightSpan, textNode);
        parent.insertBefore(reasonCard, textNode);
        parent.insertBefore(after, textNode);
        parent.removeChild(textNode);

        break; // Move to next sentence result
      }
    }
  }

  /**
   * Format signal name for display.
   */
  function formatSignalName(signal) {
    const names = {
      ai_detected: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8z"></path><path d="M12 6a6 6 0 0 0-6 6"></path></svg> Neural Net',
      urgency: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> Time Constraint',
      fear: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg> Coercion',
      suspicious_url: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg> Bad Origin',
      authority_mismatch: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg> Identity Spoof',
      authority_claim: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg> Authority Claim',
    };
    return names[signal] || signal;
  }

  // ═══════════════════════════════════════════════════════════
  // §9B  SIDE PANEL — RISK GAUGE + SIGNAL BREAKDOWN
  // ═══════════════════════════════════════════════════════════

  let _panelEl = null;
  let _toggleEl = null;
  let _panelOpen = false;

  /**
   * Get the risk color based on a normalized score [0, 1].
   * Smoothly interpolates green → yellow → red.
   */
  function getRiskColor(normalizedScore) {
    if (normalizedScore <= 0.33) return 'var(--pl-green)';
    if (normalizedScore <= 0.66) return 'var(--pl-yellow)';
    return 'var(--pl-red)';
  }

  function getRiskHSL(normalizedScore) {
    // HSL hue: 120 (green) → 45 (yellow) → 0 (red)
    const hue = Math.round(120 - normalizedScore * 120);
    return `hsl(${hue}, 85%, 55%)`;
  }

  /**
   * Create the floating toggle button for the side panel.
   */
  function createToggleButton() {
    if (_toggleEl) return _toggleEl;

    _toggleEl = document.createElement('button');
    _toggleEl.className = 'phishlens-panel-toggle';
    _toggleEl.id = 'phishlens-panel-toggle';
    _toggleEl.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M12 8v4"></path><path d="M12 16h.01"></path></svg>';
    _toggleEl.title = 'Open PhishLens Panel';

    _toggleEl.addEventListener('click', () => {
      togglePanel();
    });

    document.body.appendChild(_toggleEl);
    return _toggleEl;
  }

  /**
   * Toggle the side panel open/closed.
   */
  function togglePanel() {
    if (!_panelEl) return;
    _panelOpen = !_panelOpen;

    if (_panelOpen) {
      _panelEl.classList.add('phishlens-panel-open');
      if (_toggleEl) _toggleEl.style.right = '370px';
    } else {
      _panelEl.classList.remove('phishlens-panel-open');
      if (_toggleEl) _toggleEl.style.right = '0';
    }
  }

  function initWebGLBackground() {
    const canvas = document.getElementById('phishlens-bg-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    let w = canvas.width = 380;
    let h = canvas.height = window.innerHeight;

    window.addEventListener('resize', () => {
      h = canvas.height = window.innerHeight;
    });

    const dots = Array(35).fill().map(() => ({
      x: Math.random() * w, y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.5, vy: (Math.random() - 0.5) * 0.5
    }));

    function draw() {
      ctx.clearRect(0, 0, w, h);
      ctx.fillStyle = 'rgba(56, 189, 248, 0.5)';
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.15)';
      dots.forEach((d, i) => {
        d.x = (d.x + d.vx + w) % w; d.y = (d.y + d.vy + h) % h;
        ctx.beginPath(); ctx.arc(d.x, d.y, 2, 0, Math.PI * 2); ctx.fill();
        dots.slice(i + 1).forEach(d2 => {
          const dist = Math.hypot(d.x - d2.x, d.y - d2.y);
          if (dist < 100) { ctx.beginPath(); ctx.moveTo(d.x, d.y); ctx.lineTo(d2.x, d2.y); ctx.lineWidth = 1 - dist / 100; ctx.stroke(); }
        });
      });
      requestAnimationFrame(draw);
    }
    draw();
  }

  /**
   * Create the main side panel structure (called once).
   */
  function createSidePanel() {
    if (_panelEl) return _panelEl;

    _panelEl = document.createElement('div');
    _panelEl.className = 'phishlens-panel';
    _panelEl.id = 'phishlens-panel';

    _panelEl.innerHTML = `
      <canvas id="phishlens-bg-canvas"></canvas>
      <div class="phishlens-panel-content">
        <div class="phishlens-panel-header">
          <div class="phishlens-panel-logo">
            <span class="phishlens-panel-logo-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M12 8v4"></path><path d="M12 16h.01"></path></svg></span>
            <div class="phishlens-panel-logo-text">
              <span class="phishlens-panel-logo-name">Aegis AI</span>
              <span class="phishlens-panel-logo-sub">Interceptor</span>
            </div>
          </div>
          <button class="phishlens-panel-close" id="phishlens-panel-close-btn" title="Close panel">&times;</button>
        </div>
        <div class="phishlens-panel-body" id="phishlens-panel-body">
          <div class="phishlens-panel-empty">
            <div class="phishlens-panel-empty-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg></div>
            <div class="phishlens-panel-empty-text">
              Awaiting neural<br>vector analysis
            </div>
          </div>
        </div>
        <div class="phishlens-panel-footer">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg> Local Neural processing active
        </div>
      </div>
    `;

    // Close button
    _panelEl.querySelector('#phishlens-panel-close-btn').addEventListener('click', () => {
      togglePanel();
    });

    document.body.appendChild(_panelEl);
    createToggleButton();

    // Initialize WebGL background
    initWebGLBackground();

    return _panelEl;
  }

  /**
   * Build the SVG circular gauge meter.
   * @param {number} score - The current risk score
   * @param {number} maxScore - The maximum possible score
   * @param {string} level - 'low', 'medium', or 'high'
   */
  function buildGaugeHTML(score, maxScore, level) {
    // Semicircle arc: radius 80, center at (90, 90)
    // Arc from 180° to 0° (left to right, bottom half)
    const r = 75;
    const cx = 90;
    const cy = 90;

    // Half-circle path length
    const circumference = Math.PI * r; // ~235.6

    // Normalized score (0 to 1)
    const cappedScore = Math.min(score, maxScore);
    const normalized = cappedScore / maxScore;

    // How much of the arc to fill
    const fillLength = circumference * normalized;
    const dashOffset = circumference - fillLength;

    // Pick color
    const color = getRiskHSL(normalized);

    const levelClass = `phishlens-gauge-level-${level}`;
    const levelText = level === 'low' ? 'Safe' : level === 'medium' ? 'Suspicious' : 'High Risk';

    return `
      <div class="phishlens-gauge-container">
        <div class="phishlens-gauge">
          <svg viewBox="0 0 180 110">
            <path
              class="phishlens-gauge-bg"
              d="M 15,90 A ${r},${r} 0 0,1 165,90"
            />
            <path
              class="phishlens-gauge-fill"
              d="M 15,90 A ${r},${r} 0 0,1 165,90"
              stroke="${color}"
              stroke-dasharray="${circumference}"
              stroke-dashoffset="${dashOffset}"
              style="animation: phishlens-gauge-appear 1.2s cubic-bezier(0.4, 0, 0.2, 1) forwards;"
            />
          </svg>
          <div class="phishlens-gauge-label">
            <div class="phishlens-gauge-score" style="color: ${color}">${Math.round(normalized * 100)}%</div>
          </div>
        </div>
        <span class="phishlens-gauge-level ${levelClass}">${levelText}</span>
      </div>
    `;
  }

  /**
   * Build the stats row HTML.
   */
  function buildStatsHTML(overall) {
    return `
      <div class="phishlens-stats-row">
        <div class="phishlens-stat-card">
          <div class="phishlens-stat-value" style="color: var(--pl-text-light)">${overall.sentenceCount}</div>
          <div class="phishlens-stat-label">Sentences</div>
        </div>
        <div class="phishlens-stat-card">
          <div class="phishlens-stat-value" style="color: var(--pl-red)">${overall.highCount}</div>
          <div class="phishlens-stat-label">High Risk</div>
        </div>
        <div class="phishlens-stat-card">
          <div class="phishlens-stat-value" style="color: var(--pl-yellow)">${overall.mediumCount}</div>
          <div class="phishlens-stat-label">Suspicious</div>
        </div>
      </div>
    `;
  }

  /**
   * Build the signal breakdown HTML.
   */
  function buildSignalsHTML(results) {
    return ''; // Feature removed
  }

  /**
   * Build the flagged sentences list HTML.
   */
  function buildSentencesHTML(results) {
    const risky = results.sentences.filter((r) => r.risk.level !== 'low');
    const ipRisks = results.ipThreats || [];
    const senderIP = results.senderIPThreat;

    let html = '';

    const nonSenderIPs = ipRisks.filter(ip => !ip.isSender);

    if (nonSenderIPs.length > 0) {
      html += `<div class="phishlens-section-title">Other Flagged IP Addresses (${nonSenderIPs.length})</div><div class="phishlens-sentence-list">`;
      for (const ipRisk of nonSenderIPs) {
        const level = (ipRisk.label === 'Block' || ipRisk.label === 'Restrict') ? 'high' : 'medium';
        const cardClass = `phishlens-sentence-card-${level}`;
        const scoreClass = `phishlens-sentence-score-${level}`;
        const levelLabel = level === 'high' ? '🚨 HIGH' : '⚠️ MED';
        html += `
          <div class="phishlens-sentence-card ${cardClass}">
            <div class="phishlens-sentence-text">Source IP: ${escapeHTML(ipRisk.ip)}</div>
            <div class="phishlens-sentence-meta">
              <span class="phishlens-sentence-score ${scoreClass}">${levelLabel} · ${escapeHTML(ipRisk.label)}</span>
              <span class="phishlens-sentence-explanation">Identified as a malicious or suspicious IP address.</span>
            </div>
          </div>
        `;
      }
      html += '</div>';
    }

    if (risky.length === 0 && nonSenderIPs.length === 0) {
      return html + `
        <div class="phishlens-section-title">Text Analysis Results</div>
        <div style="text-align: center; padding: 16px; color: var(--pl-text-dim); font-size: 12px;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;display:inline-block;vertical-align:middle;margin-right:8px;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg> No textual threat signatures isolated.
        </div>
      `;
    }

    if (risky.length > 0) {
      html += `<div class="phishlens-section-title">Flagged Sentences (${risky.length})</div><div class="phishlens-sentence-list">`;

      for (const r of risky) {
        const cardClass = `phishlens-sentence-card-${r.risk.level}`;
        const scoreClass = `phishlens-sentence-score-${r.risk.level}`;
        const levelLabel = r.risk.level === 'high' ? '🚨 HIGH' : '⚠️ MED';
        const truncated = r.sentence.length > 120 ? r.sentence.substring(0, 120) + '…' : r.sentence;

        const shapHtml = r.shapPhrases && r.shapPhrases.length > 0
          ? `<div style="margin-top:8px; display:flex; flex-direction:column; gap:4px;">` + r.shapPhrases.map(s =>
            `<div style="display:flex; flex-direction:column; font-size:11px; padding:6px 10px; background:rgba(239,68,68,0.05); border-radius:6px; border-left:2px solid rgba(239,68,68,0.5);">
               <span style="color:#ef4444; font-weight:700; margin-bottom:2px;">Flagged Phrase: "${escapeHTML(s.phrase)}"</span>
               <span style="color:#94a3b8;">${escapeHTML(s.explanation)}</span>
             </div>`
          ).join('') + `</div>`
          : '';

        html += `
          <div class="phishlens-sentence-card ${cardClass}">
            <div class="phishlens-sentence-text">${escapeHTML(truncated)}</div>
            <div class="phishlens-sentence-meta">
              <span class="phishlens-sentence-score ${scoreClass}">${levelLabel} · Score ${Math.round(r.risk.score)}%</span>
              ${r.explanation ? `<span class="phishlens-sentence-explanation">${escapeHTML(r.explanation.substring(0, 80))}</span>` : ''}
            </div>
            ${shapHtml}
          </div>
        `;
      }

      html += '</div>';
    }

    return html;
  }

  /**
   * Escape HTML special characters.
   */
  function escapeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  /**
   * Populate the side panel with analysis results.
   */
  function updateSidePanel(results) {
    createSidePanel();

    const body = document.getElementById('phishlens-panel-body');
    if (!body) return;

    // Scores are now 0-100 (DistilBERT-primary). Use peak sentence score for gauge.
    const maxPossibleScore = 100;
    const displayScore = results.sentences.reduce((max, r) => Math.max(max, r.risk.score), 0);

    const senderIP = results.senderIPThreat;
    let senderIPHTML = '';

    // PROMINENT SENDER IP BLOCK
    if (senderIP) {
       const isSafe = (senderIP.label === 'Allow' || senderIP.label === 'Unknown');
       const levelClass = isSafe ? 'safe' : (senderIP.label === 'Monitor' ? 'medium' : 'high');
       const icon = isSafe 
            ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:24px;height:24px;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>` 
            : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:24px;height:24px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;

       let displayLabel = senderIP.label;
       let displayIP = senderIP.ip;
       if (displayLabel === 'Unknown') displayLabel = 'Unclassified';
       if (displayIP === 'Not Detected') displayIP = '—';

       const statusDescriptions = {
         'Allow': 'Verified · No Threats Found',
         'Monitor': 'Caution · Under Surveillance',
         'Restrict': 'Flagged · Access Restricted',
         'Block': 'Blocked · Known Threat Actor',
         'Unclassified': 'No Threat Intelligence Available',
       };
       const statusDesc = statusDescriptions[displayLabel] || 'Pending Classification';

       senderIPHTML = `
         <div style="margin: 12px 16px; padding: 0; border-radius: 14px; background: linear-gradient(135deg, rgba(15, 23, 42, 0.7), rgba(30, 41, 59, 0.5)); border: 1px solid rgba(148,163,184,0.12); overflow: hidden; font-family: 'Inter', system-ui, -apple-system, sans-serif; box-shadow: 0 4px 24px rgba(0,0,0,0.15);">

            <!-- Header Bar -->
            <div style="padding: 10px 16px; background: rgba(148,163,184,0.06); border-bottom: 1px solid rgba(148,163,184,0.08); display: flex; align-items: center; gap: 8px;">
               <svg viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="1.5" style="width:14px;height:14px;"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
               <span style="font-size: 10px; text-transform: uppercase; letter-spacing: 1.5px; color: #64748b; font-weight: 600;">Origin Network Address</span>
            </div>

            <!-- Body -->
            <div style="padding: 16px; display: flex; align-items: center; gap: 14px;">
               <div style="flex-shrink: 0; width: 44px; height: 44px; border-radius: 12px; background: var(--pl-bg-${levelClass}); display: flex; align-items: center; justify-content: center; color: var(--pl-${levelClass}); box-shadow: 0 0 16px var(--pl-bg-${levelClass});">
                  ${icon}
               </div>
               <div style="flex-grow: 1; min-width: 0;">
                  <div style="font-size: 22px; font-weight: 800; color: #f1f5f9; font-family: 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace; letter-spacing: 1px; margin-bottom: 6px; line-height: 1;">${displayIP === '—' ? '<span style="color:#475569;">Unavailable</span>' : escapeHTML(displayIP)}</div>
                  <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                     <span style="font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.2px; padding: 3px 8px; border-radius: 4px; background: var(--pl-bg-${levelClass}); color: var(--pl-${levelClass}); border: 1px solid var(--pl-${levelClass});">${escapeHTML(displayLabel)}</span>
                     <span style="font-size: 11px; color: #94a3b8; font-weight: 400;">${statusDesc}</span>
                  </div>
               </div>
            </div>

            <!-- Footer -->
            <div style="padding: 8px 16px; background: rgba(148,163,184,0.04); border-top: 1px solid rgba(148,163,184,0.06); display: flex; align-items: center; gap: 6px;">
               <svg viewBox="0 0 24 24" fill="none" stroke="#475569" stroke-width="1.5" style="width:12px;height:12px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
               <span style="font-size: 10px; color: #475569; font-weight: 500; letter-spacing: 0.5px;">Threat Intelligence Classification · PhishLens AI Engine</span>
            </div>

         </div>
       `;
    }

    // Build panel content
    body.innerHTML =
      senderIPHTML +
      buildGaugeHTML(displayScore, maxPossibleScore, results.overall.level) +
      buildStatsHTML(results.overall) +
      buildSentencesHTML(results);

    // Update toggle button color
    if (_toggleEl) {
      _toggleEl.classList.remove('phishlens-toggle-danger', 'phishlens-toggle-warning', 'phishlens-toggle-safe');
      if (results.overall.level === 'high') {
        _toggleEl.classList.add('phishlens-toggle-danger');
        _toggleEl.title = 'PhishLens: High Risk Detected!';
      } else if (results.overall.level === 'medium') {
        _toggleEl.classList.add('phishlens-toggle-warning');
        _toggleEl.title = 'PhishLens: Suspicious Content Found';
      } else {
        _toggleEl.classList.add('phishlens-toggle-safe');
        _toggleEl.title = 'PhishLens: Email Looks Safe';
      }
    }

    // Auto-open the panel on high risk
    if (results.overall.level === 'high' && !_panelOpen) {
      togglePanel();
    }
  }

  // ═══════════════════════════════════════════════════════════
  // §10  GMAIL INTEGRATION — MUTATION OBSERVER
  // ═══════════════════════════════════════════════════════════

  let lastProcessedEmailId = null;
  let isProcessing = false;
  let _isModifyingDOM = false;
  let debounceTimer = null;
  let lastKnownURL = '';

  /**
   * Extract clean text from email body element.
   */
  function extractEmailText(emailBodyEl) {
    if (!emailBodyEl) return '';

    // Clone to avoid modifying the original
    const clone = emailBodyEl.cloneNode(true);

    // Remove quoted replies (usually in .gmail_quote)
    const quotes = clone.querySelectorAll('.gmail_quote');
    quotes.forEach((q) => q.remove());

    // Remove PhishLens non-text elements (tooltips, inline explanations, banners)
    // These don't contain original email text
    clone.querySelectorAll('.phishlens-tooltip, .phishlens-inline-explanation, .phishlens-banner, .phishlens-loader').forEach((el) => el.remove());

    // Unwrap highlight spans — keep their text content.
    // Removing them would delete original email text and change the hash.
    clone.querySelectorAll('.phishlens-highlight').forEach((el) => {
      const parent = el.parentNode;
      while (el.firstChild) {
        parent.insertBefore(el.firstChild, el);
      }
      parent.removeChild(el);
    });

    // Get text content
    let text = clone.innerText || clone.textContent || '';

    // Clean up whitespace
    text = text
      .replace(/\r\n/g, '\n')
      .replace(/\n{3,}/g, '\n\n')
      .replace(/[\t ]+/g, ' ')
      .trim();

    return text;
  }

  /**
   * Generate a simple hash of string for deduplication.
   */
  function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const chr = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + chr;
      hash |= 0;
    }
    return hash.toString();
  }

  /**
   * Main processing function — triggered when a new email is detected.
   */
  async function processEmail(emailBodyEl) {
    if (isProcessing) return;

    const text = extractEmailText(emailBodyEl);
    if (!text || text.length < 20) return;

    // Deduplication — don't re-process the same email content
    const emailHash = simpleHash(text);
    if (emailHash === lastProcessedEmailId) return;

    isProcessing = true;
    lastProcessedEmailId = emailHash;

    console.log('[PhishLens] 📧 New email detected, starting analysis…');
    console.log('[PhishLens] Text length:', text.length, 'characters');

    // Guard: prevent our own DOM changes from re-triggering the observer
    _isModifyingDOM = true;

    // Remove existing PhishLens elements
    document.querySelectorAll('.phishlens-banner, .phishlens-loader, .phishlens-inline-explanation').forEach((el) => el.remove());
    document.querySelectorAll('.phishlens-highlight').forEach((el) => {
      // Unwrap — replace span with its text content
      const parent = el.parentNode;
      const textNode = document.createTextNode(el.textContent);
      parent.replaceChild(textNode, el);
      parent.normalize();
    });

    _isModifyingDOM = false;

    // Show loader
    _isModifyingDOM = true;
    const loader = createLoader();
    emailBodyEl.parentElement.insertBefore(loader, emailBodyEl);
    _isModifyingDOM = false;

    try {
      // Run analysis
      const startTime = performance.now();
      const results = await analyzeEmail(text, emailBodyEl);
      const elapsed = (performance.now() - startTime).toFixed(0);

      console.log(`[PhishLens] ✅ Analysis complete in ${elapsed}ms`);
      console.log(`[PhishLens] Overall: ${results.overall.level.toUpperCase()} (score: ${results.overall.totalScore})`);
      console.log(`[PhishLens] Sentences: ${results.overall.sentenceCount} total, ${results.overall.highCount} high-risk, ${results.overall.mediumCount} medium-risk`);

      // Guard DOM modifications
      _isModifyingDOM = true;

      // Remove loader
      removeLoader();

      // Insert banner
      const banner = createBanner(results.overall);
      emailBodyEl.parentElement.insertBefore(banner, emailBodyEl);

      // Highlight sentences
      highlightSentences(emailBodyEl, results);

      _isModifyingDOM = false;

      // Update side panel with results
      updateSidePanel(results);

      // Log detailed results for debugging
      const riskyResults = results.sentences.filter((r) => r.risk.level !== 'low');
      if (riskyResults.length > 0) {
        console.group('[PhishLens] 🔍 Detailed Results');
        for (const r of riskyResults) {
          console.log(`  [${r.risk.level.toUpperCase()}] Score: ${r.risk.score} | "${r.sentence.substring(0, 80)}…"`);
          console.log(`    Signals: ${r.risk.activeSignals.join(', ')}`);
          console.log(`    Explanation: ${r.explanation}`);
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

  /**
   * Check if an email is currently open and process it.
   * Uses content hashing to detect when email content has changed,
   * even if Gmail reuses the same DOM container.
   */
  function checkForEmail() {
    if (_isModifyingDOM || isProcessing) return;

    const emailBodies = document.querySelectorAll(CONFIG.EMAIL_BODY_SELECTOR);
    if (emailBodies.length === 0) return;

    // Get the last (most recently opened) email body
    const emailBodyEl = emailBodies[emailBodies.length - 1];

    // Verify it has content
    const rawText = (emailBodyEl.innerText || '').trim();
    if (rawText.length < 20) return;

    // Use the same clean extraction as processEmail for a stable hash
    const cleanText = extractEmailText(emailBodyEl);
    const quickHash = simpleHash(cleanText);
    if (quickHash === lastProcessedEmailId) return;

    processEmail(emailBodyEl);
  }

  /**
   * Debounced check for email changes.
   */
  function debouncedCheck() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(checkForEmail, CONFIG.DEBOUNCE_MS);
  }

  /**
   * Initialize MutationObserver to watch for Gmail navigation
   * and email opening events.
   */
  function initObserver() {
    // Watch for ANY DOM changes in the body — Gmail reuses containers
    // and doesn't always create new elements for new emails
    const observer = new MutationObserver((mutations) => {
      // Skip ALL mutations while PhishLens is modifying the DOM
      if (_isModifyingDOM || isProcessing) return;

      let shouldCheck = false;

      for (const mutation of mutations) {
        // Skip our own mutations (PhishLens elements)
        if (mutation.target && mutation.target.className &&
          typeof mutation.target.className === 'string' &&
          mutation.target.className.includes('phishlens-')) {
          continue;
        }

        // Skip if added node is a PhishLens element
        let isPhishLensNode = false;
        if (mutation.addedNodes.length > 0) {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE && node.className &&
              typeof node.className === 'string' &&
              node.className.includes('phishlens-')) {
              isPhishLensNode = true;
              break;
            }
          }
        }
        if (isPhishLensNode) continue;

        // Check added nodes for email body elements
        if (mutation.addedNodes.length > 0) {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE) {
              if (
                node.matches?.(CONFIG.EMAIL_BODY_SELECTOR) ||
                node.querySelector?.(CONFIG.EMAIL_BODY_SELECTOR) ||
                node.closest?.(CONFIG.EMAIL_BODY_SELECTOR)
              ) {
                shouldCheck = true;
                break;
              }
              // Also check for Gmail's content containers being swapped
              if (node.classList && (
                node.classList.contains('nH') ||
                node.classList.contains('adn') ||
                node.classList.contains('a3s')
              )) {
                shouldCheck = true;
                break;
              }
            }
          }
        }

        // Also check if characterData changed inside an email body
        if (mutation.type === 'characterData' || mutation.type === 'childList') {
          const target = mutation.target;
          if (target && target.nodeType === Node.ELEMENT_NODE &&
            target.closest && target.closest(CONFIG.EMAIL_BODY_SELECTOR)) {
            shouldCheck = true;
          } else if (target && target.parentElement &&
            target.parentElement.closest &&
            target.parentElement.closest(CONFIG.EMAIL_BODY_SELECTOR)) {
            shouldCheck = true;
          }
        }

        if (shouldCheck) break;
      }

      if (shouldCheck) {
        debouncedCheck();
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
    });

    console.log('[PhishLens] 👁️ MutationObserver active — watching for emails');

    // Also check immediately in case email is already open
    setTimeout(checkForEmail, 1000);

    // Listen for hashchange (Gmail navigation)
    window.addEventListener('hashchange', () => {
      console.log('[PhishLens] 📍 URL changed (hashchange)');
      lastProcessedEmailId = null;
      setTimeout(debouncedCheck, 500);
    });

    // Gmail doesn't always fire hashchange — poll for URL changes
    lastKnownURL = location.href;
    setInterval(() => {
      if (location.href !== lastKnownURL) {
        console.log('[PhishLens] 📍 URL changed (poll detected)');
        lastKnownURL = location.href;
        lastProcessedEmailId = null;
        debouncedCheck();
      }
    }, 2000);

    // Periodic fallback check — catches edge cases where Gmail
    // swaps content without triggering observable DOM mutations
    setInterval(() => {
      if (!isProcessing) {
        checkForEmail();
      }
    }, 5000);
  }

  // ═══════════════════════════════════════════════════════════
  // §11  INBOX HOVER LOGIC
  // ═══════════════════════════════════════════════════════════

  let _inboxPopup = null;
  let _hoverTimeout = null;
  let _currentRowHovered = null;

  function createInboxPopup() {
    if (_inboxPopup) return _inboxPopup;
    _inboxPopup = document.createElement('div');
    _inboxPopup.id = 'phishlens-inbox-popup';
    _inboxPopup.className = 'phishlens-tooltip';
    _inboxPopup.style.position = 'fixed';
    _inboxPopup.style.pointerEvents = 'none';
    _inboxPopup.style.zIndex = '100000';
    _inboxPopup.style.transform = 'none';
    _inboxPopup.style.bottom = 'auto'; // Disable default tooltip bottom
    _inboxPopup.style.left = 'auto';
    document.body.appendChild(_inboxPopup);
    return _inboxPopup;
  }

  function hideInboxPopup() {
    if (_inboxPopup) {
      _inboxPopup.style.opacity = '0';
      setTimeout(() => { if (_inboxPopup && _inboxPopup.style.opacity === '0') _inboxPopup.style.display = 'none'; }, 200);
    }
  }

  async function handleInboxRowHover(row, e) {
    if (_currentRowHovered === row) {
      // Follow cursor while hovering
      if (_inboxPopup && _inboxPopup.style.opacity === '1') {
        _inboxPopup.style.left = (e.clientX + 15) + 'px';
        _inboxPopup.style.top = (e.clientY + 15) + 'px';
      }
      return;
    }

    _currentRowHovered = row;
    clearTimeout(_hoverTimeout);
    hideInboxPopup();

    _hoverTimeout = setTimeout(async () => {
      // Re-verify hovering
      if (_currentRowHovered !== row) return;

      // Extract details
      const senderEl = row.querySelector('.bA4 span, div.yW span');
      const subjectEl = row.querySelector('span.bog');
      const snippetEl = row.querySelector('span.y2');

      const sender = senderEl ? senderEl.innerText : '';
      const subject = subjectEl ? subjectEl.innerText : '';
      const snippet = snippetEl ? snippetEl.innerText.replace(/^- /, '') : '';

      const fullText = `${sender}. ${subject}. ${snippet}`;
      if (fullText.length < 10) return;

      const popup = createInboxPopup();
      popup.style.display = 'block';
      popup.style.left = (e.clientX + 15) + 'px';
      popup.style.top = (e.clientY + 15) + 'px';
      popup.style.opacity = '1';
      popup.innerHTML = `
        <div class="phishlens-tooltip-header">
           <svg viewBox="0 0 24 24" fill="none" class="phishlens-spinner" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle></svg> 
           Scanning with Aegis AI...
        </div>`;

      try {
        const results = await analyzeEmail(fullText);

        if (_currentRowHovered !== row) return; // User moved away

        const level = results.overall.level;
        // Use the PEAK individual sentence score natively (0-100)
        const peakSentenceScore = results.sentences.reduce(
          (max, r) => Math.max(max, r.risk.score), 0
        );
        const percentage = Math.min(100, Math.round(peakSentenceScore));

        // Confidence label: bump up slightly when multiple sentences flagged,
        // but never exceed what the card would show for the worst sentence.
        const highCount = results.overall.highCount;
        const medCount = results.overall.mediumCount;
        const totalFlagged = highCount + medCount;
        const confidenceNote = totalFlagged > 1
          ? ` · ${totalFlagged} vectors`
          : '';

        const headerClass = level === 'high' ? 'phishlens-tooltip-header-high' : level === 'medium' ? 'phishlens-tooltip-header-medium' : '';
        const icon = level === 'high' ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>' :
          level === 'medium' ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>' :
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>';

        let label = 'SECURE';
        if (level === 'high') label = 'CRITICAL VECTOR';
        else if (level === 'medium') label = 'SUSPICIOUS PATTERN';

        // Pick the worst flagged sentence for explanation
        const riskySentence = results.sentences
          .filter(r => r.risk.level !== 'low')
          .sort((a, b) => b.risk.score - a.risk.score)[0];

        let desc = 'Snippet analysis shows no immediate threats.';
        if (riskySentence) desc = riskySentence.explanation;

        // Build signal chips for the worst sentence
        const chips = riskySentence
          ? riskySentence.risk.activeSignals.map(s => {
            const lbl = formatSignalName(s).replace(/<[^>]+>/g, '').trim();
            return `<span style="display:inline-flex;padding:1px 7px;border-radius:4px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);font-size:10px;font-family:monospace;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;">${lbl}</span>`;
          }).join('')
          : '';

        const shapHtmlPopup = riskySentence && riskySentence.shapPhrases && riskySentence.shapPhrases.length > 0
          ? `<div style="margin-top:8px; padding-top:8px; border-top:1px solid rgba(255,255,255,0.1); text-align:center;">
               <span style="color:#ef4444; font-size:10px; font-weight:bold; letter-spacing:0.5px; text-transform:uppercase;">Flagged Phrase</span>
               <div style="margin-top:2px; font-family:monospace; color:#f8fafc; font-size:11px;">"${escapeHTML(riskySentence.shapPhrases[0].phrase)}"</div>
             </div>` : '';

        popup.innerHTML = `
          <div class="phishlens-tooltip-header ${headerClass}">
            ${icon} ${label} · ${percentage}%${confidenceNote}
          </div>
          <div class="phishlens-tooltip-body">${desc}</div>
          ${chips ? `<div class="phishlens-tooltip-signals" style="margin-top:8px;display:flex;flex-wrap:wrap;gap:5px;">${chips}</div>` : ''}
          ${shapHtmlPopup}
        `;

      } catch (err) {
        hideInboxPopup();
      }
    }, 600); // Wait 600ms hovering before scanning
  }

  function initInboxHover() {
    document.addEventListener('mouseover', (e) => {
      const target = e.target;
      if (target && target.closest) {
        const row = target.closest('tr.zA');
        if (row) {
          handleInboxRowHover(row, e);
        }
      }
    });

    document.addEventListener('mousemove', (e) => {
      if (_inboxPopup && _inboxPopup.style.opacity === '1') {
        const target = e.target;
        if (target && target.closest) {
          const row = target.closest('tr.zA');
          if (row === _currentRowHovered) {
            _inboxPopup.style.left = (e.clientX + 15) + 'px';
            _inboxPopup.style.top = (e.clientY + 15) + 'px';
          } else {
            _currentRowHovered = null;
            hideInboxPopup();
          }
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════
  // §12  INITIALIZATION
  // ═══════════════════════════════════════════════════════════

  /**
   * Wait for Gmail to fully load, then initialize the observer.
   */
  function init() {
    // Gmail can take a moment to load its UI
    const checkReady = setInterval(() => {
      // Look for Gmail's main content area
      const gmailReady =
        document.querySelector('[role="main"]') ||
        document.querySelector('.nH') ||
        document.querySelector('.AO');

      if (gmailReady) {
        clearInterval(checkReady);
        console.log('[PhishLens] 🚀 Gmail detected — initializing PhishLens');
        createSidePanel();
        initObserver();
        initInboxHover();
      }
    }, 500);

    // Safety timeout — give up after 30 seconds
    setTimeout(() => clearInterval(checkReady), 30000);
  }

  // Start!
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
