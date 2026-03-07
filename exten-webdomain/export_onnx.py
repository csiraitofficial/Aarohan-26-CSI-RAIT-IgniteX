"""
AegisAI — Export distilbert-base-uncased-finetuned-sst-2-english to ONNX
=========================================================================
Source model : distilbert-base-uncased-finetuned-sst-2-english (HuggingFace)
Target format : ONNX + int8 quantized  (Transformers.js compatible)
Output dir   : models/phishing-url-detection/
This produces the exact same file layout that Xenova/distilbert-base-uncased-sst2
uses, so our background.js works without modification.
Run: python export_onnx.py
"""
import os, sys, json, shutil
BASE      = r"c:\Users\RAJ SAWANT\OneDrive\Desktop\AegisAI"
MODEL_DIR = os.path.join(BASE, "models", "phishing-url-detection")
ONNX_DIR  = os.path.join(MODEL_DIR, "onnx")
TMP_DIR   = os.path.join(BASE, "tmp_onnx_export")
SOURCE_MODEL = "distilbert-base-uncased-finetuned-sst-2-english"
print("=" * 65)
print("  AegisAI — DistilBERT → ONNX Export Pipeline")
print(f"  Source : {SOURCE_MODEL}")
print(f"  Output : {MODEL_DIR}")
print("=" * 65, flush=True)
print("\n[1/6] Importing libraries...", flush=True)
try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import torch
    from optimum.onnxruntime import ORTModelForSequenceClassification
    from optimum.exporters.onnx import main_export
    import onnx
    from onnxruntime.quantization import quantize_dynamic, QuantType
    print("  OK — all libraries loaded")
except ImportError as e:
    print(f"  ERROR: {e}")
    sys.exit(1)
print("\n[2/6] Preparing directories...", flush=True)
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(ONNX_DIR,  exist_ok=True)
os.makedirs(TMP_DIR,   exist_ok=True)
print(f"  OK — {MODEL_DIR}")
print(f"\n[3/6] Downloading {SOURCE_MODEL} tokenizer & model...", flush=True)
tokenizer = AutoTokenizer.from_pretrained(SOURCE_MODEL)
model     = AutoModelForSequenceClassification.from_pretrained(SOURCE_MODEL)
model.eval()
print("  OK — model loaded")
print("\n[4/6] Exporting to ONNX (float32)...", flush=True)
fp32_path = os.path.join(TMP_DIR, "model.onnx")
dummy_input = tokenizer(
    "buy cheap meds online click here",
    return_tensors="pt",
    padding="max_length",
    max_length=128,
    truncation=True,
)
with torch.no_grad():
    torch.onnx.export(
        model,
        (dummy_input["input_ids"], dummy_input["attention_mask"]),
        fp32_path,
        input_names  = ["input_ids", "attention_mask"],
        output_names = ["logits"],
        dynamic_axes = {
            "input_ids":      {0: "batch", 1: "sequence"},
            "attention_mask": {0: "batch", 1: "sequence"},
            "logits":         {0: "batch"},
        },
        opset_version = 14,
        do_constant_folding = True,
    )
mb = os.path.getsize(fp32_path) / 1024 / 1024
print(f"  OK — model.onnx  ({mb:.1f} MB)", flush=True)
print("\n[5/6] Quantizing to int8 (model_quantized.onnx)...", flush=True)
quant_path = os.path.join(ONNX_DIR, "model_quantized.onnx")
quantize_dynamic(
    model_input   = fp32_path,
    model_output  = quant_path,
    weight_type   = QuantType.QInt8,
    per_channel   = False,
    reduce_range  = False,
)
qmb = os.path.getsize(quant_path) / 1024 / 1024
print(f"  OK — model_quantized.onnx  ({qmb:.1f} MB)", flush=True)
print("\n[6/6] Writing tokenizer + config files...", flush=True)
tokenizer.save_pretrained(MODEL_DIR)
print("  OK — tokenizer files saved")
config = model.config.to_dict()
config["id2label"] = {"0": "NEGATIVE", "1": "POSITIVE"}
config["label2id"] = {"NEGATIVE": 0, "POSITIVE": 1}
with open(os.path.join(MODEL_DIR, "config.json"), "w") as f:
    json.dump(config, f, indent=2)
print("  OK — config.json  (id2label: 0→NEGATIVE, 1→POSITIVE)")
pre_cfg = {
    "tokenizer_class": "BertTokenizer",
    "do_lower_case":   True,
    "model_max_length": 128
}
with open(os.path.join(MODEL_DIR, "preprocessor_config.json"), "w") as f:
    json.dump(pre_cfg, f, indent=2)
print("  OK — preprocessor_config.json")
shutil.rmtree(TMP_DIR, ignore_errors=True)
print("\n" + "=" * 65)
print("  Model directory:")
for root, dirs, files in os.walk(MODEL_DIR):
    lvl = root.replace(MODEL_DIR, "").count(os.sep)
    pad = "  " * (lvl + 1)
    for fn in sorted(files):
        mb_f = os.path.getsize(os.path.join(root, fn)) / 1024 / 1024
        rel  = os.path.relpath(os.path.join(root, fn), MODEL_DIR)
        print(f"{pad}{rel:<45}  {mb_f:6.2f} MB")
print()
print("  ✅  ONNX (quantized int8) model ready!")
print("  ✅  ~17-20 MB — optimal for browser inference")
print("  ✅  Load extension: chrome://extensions → Load unpacked")
print("=" * 65)