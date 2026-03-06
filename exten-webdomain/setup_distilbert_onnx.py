"""
AegisAI - Download Xenova/distilbert-base-uncased-sst2 ONNX model
Uses huggingface_hub for authenticated anonymous access.

Run:
    python setup_distilbert_onnx.py
"""

import os, sys, json
from huggingface_hub import hf_hub_download

REPO_ID   = "Xenova/distilbert-base-uncased-sst2"
BASE      = r"c:\Users\RAJ SAWANT\OneDrive\Desktop\AegisAI"
MODEL_DIR = os.path.join(BASE, "models", "phishing-url-detection")
ONNX_DIR  = os.path.join(MODEL_DIR, "onnx")

# Files Transformers.js needs for text-classification
FILES = [
    "config.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.txt",
    "special_tokens_map.json",
    "onnx/model_quantized.onnx",   # ~17 MB int8 quantized — fastest in browser
]

def pull(filename):
    dest = os.path.join(MODEL_DIR, filename.replace("/", os.sep))
    if os.path.exists(dest) and os.path.getsize(dest) > 1024:
        mb = os.path.getsize(dest) / 1024 / 1024
        print(f"  SKIP  {filename}  (already {mb:.2f} MB)")
        return dest

    print(f"  DOWN  {filename} ...", end="", flush=True)
    os.makedirs(os.path.dirname(dest), exist_ok=True)

    # hf_hub_download caches to ~/.cache/huggingface then copies
    cached = hf_hub_download(
        repo_id   = REPO_ID,
        filename  = filename,
        local_dir = MODEL_DIR,
        local_dir_use_symlinks = False,
    )
    mb = os.path.getsize(cached) / 1024 / 1024
    print(f"\r  OK    {filename}  ({mb:.2f} MB)")
    return cached

def write_preprocessor_config():
    path = os.path.join(MODEL_DIR, "preprocessor_config.json")
    with open(path, "w") as f:
        json.dump({"tokenizer_class": "BertTokenizer", "do_lower_case": True}, f, indent=2)
    print("  OK    preprocessor_config.json")

def show_tree():
    print("\nModel directory:")
    for root, dirs, files in os.walk(MODEL_DIR):
        lvl = root.replace(MODEL_DIR, "").count(os.sep)
        pad = "  " * lvl
        print(f"{pad}{os.path.basename(root)}/")
        for fn in sorted(files):
            mb = os.path.getsize(os.path.join(root, fn)) / 1024 / 1024
            print(f"{pad}  {fn}  [{mb:.2f} MB]")

def main():
    print("=" * 60)
    print("  AegisAI — DistilBERT SST-2 ONNX Download")
    print(f"  Repo : {REPO_ID}")
    print(f"  Dir  : {MODEL_DIR}")
    print("=" * 60)

    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(ONNX_DIR,  exist_ok=True)

    for f in FILES:
        try:
            pull(f)
        except Exception as e:
            print(f"\n  ERROR  {f}: {e}")
            sys.exit(1)

    write_preprocessor_config()
    show_tree()

    print("\n" + "=" * 60)
    print("  DONE! Load extension: chrome://extensions -> Load unpacked")
    print("=" * 60)

if __name__ == "__main__":
    main()
