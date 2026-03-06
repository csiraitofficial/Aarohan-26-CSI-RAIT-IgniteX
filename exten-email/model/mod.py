"""
PhishLens — ONNX Model Export Script
=====================================

Downloads a DistilBERT phishing classification model from Hugging Face
and exports it to ONNX format for in-browser inference.

Requirements:
    pip install optimum[onnxruntime] transformers torch

Usage:
    python model/mod.py

Output:
    model/model.onnx   — The ONNX model file
    model/vocab.json    — Tokenizer vocabulary for JS WordPiece tokenizer
    model/config.json   — Model config (label mapping, etc.)
"""

import json
import os
import sys

MODEL_ID = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))


def main():
    print(f"[PhishLens] Downloading model: {MODEL_ID}")
    print(f"[PhishLens] Output directory: {OUTPUT_DIR}")
    print()

    # --- Step 1: Export model to ONNX ---
    print("[1/4] Exporting model to ONNX format...")
    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification
    except ImportError:
        print("ERROR: 'optimum' is not installed.")
        print("Run: pip install optimum[onnxruntime] transformers torch")
        sys.exit(1)

    model = ORTModelForSequenceClassification.from_pretrained(
        MODEL_ID, export=True
    )
    model.save_pretrained(OUTPUT_DIR)
    print("   ✅ Model exported to ONNX")

    # --- Step 2: Extract vocabulary ---
    print("[2/4] Extracting tokenizer vocabulary...")
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    vocab = tokenizer.get_vocab()

    vocab_path = os.path.join(OUTPUT_DIR, "vocab.json")
    with open(vocab_path, "w", encoding="utf-8") as f:
        json.dump(vocab, f, ensure_ascii=False)
    print(f"   ✅ Vocabulary saved ({len(vocab)} tokens)")

    # --- Step 3: Save model config (label mapping) ---
    print("[3/4] Saving model configuration...")
    from transformers import AutoConfig

    config = AutoConfig.from_pretrained(MODEL_ID)
    config_data = {
        "id2label": config.id2label,
        "label2id": config.label2id,
        "max_position_embeddings": getattr(config, "max_position_embeddings", 512),
        "model_type": config.model_type,
    }

    config_path = os.path.join(OUTPUT_DIR, "config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)
    print(f"   ✅ Config saved (labels: {config.id2label})")

    # --- Step 4: Test inference ---
    print("[4/4] Running test inference...")
    from transformers import pipeline

    test_pipe = pipeline(
        "text-classification",
        model=MODEL_ID,
        tokenizer=tokenizer,
    )

    test_texts = [
        "Your account has been suspended. Click here to verify immediately.",
        "Hey, are we still on for lunch tomorrow at noon?",
        "URGENT: Confirm your identity or your account will be permanently deleted.",
    ]

    for text in test_texts:
        result = test_pipe(text)
        label = result[0]["label"]
        score = result[0]["score"]
        print(f'   "{text[:60]}..." → {label} ({score:.3f})')

    # --- Summary ---
    print()
    print("=" * 60)
    print("✅ Model export complete!")
    print()
    print("Files created:")

    onnx_path = os.path.join(OUTPUT_DIR, "model.onnx")
    if os.path.exists(onnx_path):
        size_mb = os.path.getsize(onnx_path) / (1024 * 1024)
        print(f"   model/model.onnx    ({size_mb:.1f} MB)")
    else:
        print("   model/model.onnx    (checking...)")
        # optimum may save as different name, list all .onnx files
        for f in os.listdir(OUTPUT_DIR):
            if f.endswith(".onnx"):
                fp = os.path.join(OUTPUT_DIR, f)
                size_mb = os.path.getsize(fp) / (1024 * 1024)
                print(f"   model/{f}    ({size_mb:.1f} MB)")

    print(f"   model/vocab.json    ({os.path.getsize(vocab_path) / 1024:.0f} KB)")
    print(f"   model/config.json")
    print()
    print("Next steps:")
    print("   1. Download ONNX Runtime Web: see lib/README.js")
    print("   2. Load the extension in Chrome")
    print("   3. Open Gmail and test with phishing emails")
    print("=" * 60)


if __name__ == "__main__":
    main()
