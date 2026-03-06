import os
import urllib.request
import urllib.error

# To ensure the browser extension doesn't need to reach out to HF Hub over
# the network (and get blocked by CORS/safety), we are pulling down the
# 17MB ONNX model and tokenizer data into a predictable directory structure
# that the Transformers.js `pipeline` will load from the `models/` folder.

repo_id = "Xenova/distilbert-base-uncased-finetuned-sst-2-english"
base_url = f"https://huggingface.co/{repo_id}/resolve/main/"
files_to_download = [
    "config.json",
    "preprocessor_config.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.txt",
    "special_tokens_map.json",
    "onnx/model_quantized.onnx"
]

output_dir = os.path.join(r"c:\Users\RAJ SAWANT\OneDrive\Desktop\AegisAI", "models", repo_id.replace("/", os.sep))

def download_files():
    print(f"Downloading {repo_id} locally to {output_dir}")
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.join(output_dir, "onnx"), exist_ok=True)

    for file_path in files_to_download:
        url = base_url + file_path
        local_path = os.path.join(output_dir, file_path.replace("/", os.sep))

        if os.path.exists(local_path):
            size_mb = os.path.getsize(local_path) / (1024 * 1024)
            print(f"Skipping {file_path} - already exists ({size_mb:.2f} MB)")
            continue

        print(f"Downloading {file_path}...", end=" ", flush=True)
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as resp, open(local_path, "wb") as f:
                content = resp.read()
                f.write(content)
            print(f"Done ({len(content) / (1024*1024):.2f} MB)")
        except urllib.error.URLError as e:
            print(f"Failed! {e.reason}")

if __name__ == "__main__":
    download_files()
