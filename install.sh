#!/bin/bash
# ============================================================
# DEFER — Full Environment Setup
# Run: conda activate agenticcyops && ./install.sh
# ============================================================

set -e

echo "[1/3] Installing PyTorch with CUDA 12.4 support..."
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124

echo "[2/3] Installing all dependencies..."
pip install -r requirements.txt

echo "[3/3] Upgrading vLLM to nightly (required for GLM-4.7)..."
pip install -U vllm --pre --index-url https://pypi.org/simple --extra-index-url https://wheels.vllm.ai/nightly

echo ""
echo "Verifying key packages..."
python -c "import torch; print(f'PyTorch {torch.__version__}, CUDA: {torch.cuda.is_available()}, GPUs: {torch.cuda.device_count()}')"
python -c "import vllm; print(f'vLLM {vllm.__version__}')"
python -c "import anthropic; print(f'Anthropic SDK {anthropic.__version__}')"
python -c "import chromadb; print(f'ChromaDB {chromadb.__version__}')"
python -c "import huggingface_hub; print(f'HuggingFace Hub {huggingface_hub.__version__}')"
python -c "import sentence_transformers; print(f'Sentence Transformers {sentence_transformers.__version__}')"

echo ""
echo "Setup complete. Next: ./download_models.sh"