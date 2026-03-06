/**
 * PhishLens — AI Inference Module
 * =================================================
 *
 * Loads the ONNX model and handles inference. This module runs
 * within the content script context, meaning it operates entirely
 * offline without requiring a background script or API calls.
 */

const AIInference = (function () {
    'use strict';

    let session = null;
    let isInitialized = false;

    // Configuration
    const MODEL_PATH = chrome.runtime.getURL('model/phishing_model.onnx');
    const VOCAB_PATH = chrome.runtime.getURL('model/vocab.json');
    const MAX_LENGTH = 128;

    async function init() {
        if (isInitialized) return;

        console.log('[PhishLens AI] Initializing AI Inference Module...');
        try {
            // Configure ONNX Runtime Web
            ort.env.wasm.wasmPaths = chrome.runtime.getURL('lib/');
            // To improve performance, cap threads and use execution provider
            ort.env.wasm.numThreads = 1;

            // Load tokenizer
            console.log('[PhishLens AI] Loading tokenizer vocab from:', VOCAB_PATH);
            await PhishLensTokenizer.loadVocab(VOCAB_PATH);

            // Load ONNX Model
            console.log('[PhishLens AI] Loading ONNX model from:', MODEL_PATH);
            const sessionOptions = {
                executionProviders: ['wasm'],
                graphOptimizationLevel: 'all'
            };
            session = await ort.InferenceSession.create(MODEL_PATH, sessionOptions);

            isInitialized = true;
            console.log('[PhishLens AI] ✅ AI Inference Module initialized and ready.');
        } catch (error) {
            console.error('[PhishLens AI] Failed to initialize AI model:', error);
            throw error;
        }
    }

    /**
     * Run inference on a given text
     * @param {string} text - Message or email body to evaluate
     * @returns {Promise<number>} - Probability of being phishing (0.0 to 1.0)
     */
    async function infer(text) {
        if (!isInitialized) {
            console.warn('[PhishLens AI] Inference called before init, initializing now...');
            await init();
        }

        if (!text || text.trim() === '') {
            return 0.0;
        }

        try {
            // 1. Tokenize
            const { inputIds, attentionMask } = PhishLensTokenizer.tokenize(text, MAX_LENGTH);

            // 2. Prepare ONNX Tensors
            // ort uses BigInt64Array for int64
            const inputIdsTensor = new ort.Tensor('int64', BigInt64Array.from(inputIds.map(BigInt)), [1, MAX_LENGTH]);
            const attentionMaskTensor = new ort.Tensor('int64', BigInt64Array.from(attentionMask.map(BigInt)), [1, MAX_LENGTH]);

            // 3. Run Inference
            const feeds = {
                "input_ids": inputIdsTensor,
                "attention_mask": attentionMaskTensor
            };

            const results = await session.run(feeds);

            // 4. Post-processing (Softmax)
            // Model outputs logits, shape [1, 2]
            const logits = results.logits.data; // Float32Array of size 2

            // Apply softmax
            const maxLogit = Math.max(logits[0], logits[1]);
            const exp0 = Math.exp(logits[0] - maxLogit);
            const exp1 = Math.exp(logits[1] - maxLogit);
            const sum = exp0 + exp1;

            const probSafe = exp0 / sum;
            const probPhishing = exp1 / sum;

            console.log(`[PhishLens AI] Analyzed message - P(Phishing): ${probPhishing.toFixed(4)}`);
            return probPhishing;
        } catch (error) {
            console.error('[PhishLens AI] Inference failed:', error);
            return 0.0; // Fail safe
        }
    }

    return {
        init,
        infer,
        isReady: () => isInitialized
    };
})();
