/**
 * PhishLens — Lightweight WordPiece Tokenizer for DistilBERT
 * ===========================================================
 *
 * A minimal JavaScript implementation of the WordPiece tokenizer
 * used by DistilBERT models. Loads vocab.json and produces
 * input_ids + attention_mask tensors for ONNX Runtime inference.
 *
 * This runs entirely in the browser — no external dependencies.
 */

// eslint-disable-next-line no-unused-vars
const PhishLensTokenizer = (function () {
    'use strict';

    // ── Special token IDs (standard BERT/DistilBERT) ──
    const SPECIAL = {
        PAD: '[PAD]',
        UNK: '[UNK]',
        CLS: '[CLS]',
        SEP: '[SEP]',
    };

    const MAX_SEQ_LENGTH = 512;
    const MAX_WORD_LEN = 100; // Skip words longer than this

    let _vocab = null;        // token → id mapping
    let _vocabLoaded = false;

    /**
     * Load vocabulary from vocab.json.
     * @param {string} vocabUrl - URL to the vocab.json file
     */
    async function loadVocab(vocabUrl) {
        if (_vocabLoaded) return;

        console.log('[PhishLens Tokenizer] Loading vocabulary…');
        const response = await fetch(vocabUrl);
        if (!response.ok) {
            throw new Error(`Failed to load vocabulary: ${response.status} ${response.statusText}`);
        }

        _vocab = await response.json();
        _vocabLoaded = true;
        console.log(`[PhishLens Tokenizer] ✅ Vocabulary loaded (${Object.keys(_vocab).length} tokens)`);
    }

    /**
     * Check if vocabulary is loaded.
     */
    function isReady() {
        return _vocabLoaded;
    }

    /**
     * Basic text preprocessing — lowercasing, punctuation splitting,
     * whitespace normalization.
     * @param {string} text
     * @returns {string[]} Array of cleaned tokens
     */
    function basicTokenize(text) {
        // Lowercase
        text = text.toLowerCase();

        // Normalize unicode whitespace
        text = text.replace(/[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]/g, ' ');

        // Add spaces around punctuation
        let result = '';
        for (let i = 0; i < text.length; i++) {
            const ch = text[i];
            const cp = ch.codePointAt(0);

            if (isPunctuation(cp)) {
                result += ' ' + ch + ' ';
            } else if (isWhitespace(cp)) {
                result += ' ';
            } else if (isControl(cp)) {
                // Skip control characters
                continue;
            } else {
                result += ch;
            }
        }

        // Split on whitespace and filter empty strings
        return result.split(/\s+/).filter((t) => t.length > 0);
    }

    /**
     * WordPiece tokenization — splits a word into subword pieces
     * using the loaded vocabulary.
     * @param {string} word
     * @returns {string[]} Array of subword tokens
     */
    function wordPieceTokenize(word) {
        if (word.length > MAX_WORD_LEN) {
            return [SPECIAL.UNK];
        }

        const tokens = [];
        let start = 0;

        while (start < word.length) {
            let end = word.length;
            let found = null;

            while (start < end) {
                let substr = word.substring(start, end);
                if (start > 0) {
                    substr = '##' + substr;
                }

                if (_vocab.hasOwnProperty(substr)) {
                    found = substr;
                    break;
                }

                end--;
            }

            if (found === null) {
                tokens.push(SPECIAL.UNK);
                break;
            }

            tokens.push(found);
            start = end;
        }

        return tokens;
    }

    /**
     * Full tokenization pipeline — text → token IDs + attention mask.
     * Produces [CLS] token_ids... [SEP] format with padding.
     *
     * @param {string} text - Input text to tokenize
     * @param {number} [maxLength=128] - Maximum sequence length (including special tokens)
     * @returns {{ inputIds: number[], attentionMask: number[] }}
     */
    function tokenize(text, maxLength) {
        if (!_vocabLoaded) {
            throw new Error('Vocabulary not loaded. Call loadVocab() first.');
        }

        maxLength = maxLength || 128;
        if (maxLength > MAX_SEQ_LENGTH) maxLength = MAX_SEQ_LENGTH;

        // Step 1: Basic tokenization (whitespace + punctuation split)
        const basicTokens = basicTokenize(text);

        // Step 2: WordPiece tokenization
        const wpTokens = [];
        for (const token of basicTokens) {
            const pieces = wordPieceTokenize(token);
            wpTokens.push(...pieces);

            // Early exit if we have enough tokens
            if (wpTokens.length >= maxLength - 2) break;
        }

        // Step 3: Truncate to maxLength - 2 (for [CLS] and [SEP])
        const truncated = wpTokens.slice(0, maxLength - 2);

        // Step 4: Add special tokens
        const fullTokens = [SPECIAL.CLS, ...truncated, SPECIAL.SEP];

        // Step 5: Convert to IDs
        const inputIds = fullTokens.map((t) => {
            if (_vocab.hasOwnProperty(t)) return _vocab[t];
            return _vocab[SPECIAL.UNK] || 0;
        });

        // Step 6: Create attention mask (1 for real tokens, 0 for padding)
        const attentionMask = new Array(inputIds.length).fill(1);

        // Step 7: Pad to maxLength
        while (inputIds.length < maxLength) {
            inputIds.push(_vocab[SPECIAL.PAD] || 0);
            attentionMask.push(0);
        }

        return { inputIds, attentionMask };
    }

    // ── Helper character classification functions ──

    function isPunctuation(cp) {
        // ASCII punctuation ranges
        if (
            (cp >= 33 && cp <= 47) ||
            (cp >= 58 && cp <= 64) ||
            (cp >= 91 && cp <= 96) ||
            (cp >= 123 && cp <= 126)
        ) {
            return true;
        }
        // Unicode general punctuation
        if (cp >= 0x2000 && cp <= 0x206F) return true;
        return false;
    }

    function isWhitespace(cp) {
        if (cp === 32 || cp === 9 || cp === 10 || cp === 13) return true;
        if (cp === 0x00A0) return true; // Non-breaking space
        return false;
    }

    function isControl(cp) {
        if (cp === 9 || cp === 10 || cp === 13) return false; // Tab, LF, CR are OK
        if (cp >= 0 && cp <= 31) return true;
        if (cp >= 127 && cp <= 159) return true;
        return false;
    }

    // ── Public API ──
    return {
        loadVocab,
        isReady,
        tokenize,
    };
})();
