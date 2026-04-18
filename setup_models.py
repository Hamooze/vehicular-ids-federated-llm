#!/usr/bin/env python3
"""
Model Setup Script - Downloads and configures LLM models for distributed IDS
Run this once before starting the services
"""

import os
import sys
import json
from pathlib import Path

MODELS_DIR = Path(__file__).parent.parent / "models"
PHI2_DIR = MODELS_DIR / "phi2"
MISTRAL_DIR = MODELS_DIR / "mistral7b"
TINYLLAMA_DIR = MODELS_DIR / "tinyllama"

MODELS_INFO = {
    "phi2": {
        "dir": PHI2_DIR,
        "file": "phi-2.Q4_K_M.gguf",
        "size": "3.3GB",
        "url": "https://huggingface.co/ggml-org/models-gguf/resolve/main/phi/phi-2.Q4_K_M.gguf",
        "recommended": True,
        "note": "Fast, good accuracy. Recommended for most use cases."
    },
    "mistral7b": {
        "dir": MISTRAL_DIR,
        "file": "mistral-7b-instruct-v0.2.Q4_K_M.gguf",
        "size": "4.7GB",
        "url": "https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.gguf",
        "recommended": False,
        "note": "Larger, higher accuracy. Better for complex prompts."
    },
    "tinyllama": {
        "dir": TINYLLAMA_DIR,
        "file": "tinyllama-1.1b-q4_k_m.gguf",
        "size": "0.7GB",
        "url": "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-q4_k_m.gguf",
        "recommended": False,
        "note": "Very small, fast. Good for testing/demo."
    }
}

def print_banner():
    print("""
╔════════════════════════════════════════════════════════════════════╗
║           LLM Model Setup for Distributed Vehicular IDS            ║
║                                                                    ║
║  This script helps you download and configure LLM models for      ║
║  the specialized IDS servers.                                     ║
╚════════════════════════════════════════════════════════════════════╝
    """)

def check_existing_models():
    """Check which models are already downloaded"""
    print("\n📋 Checking existing models...\n")
    
    existing = {}
    for model_name, info in MODELS_INFO.items():
        model_path = info["dir"] / info["file"]
        if model_path.exists():
            size = model_path.stat().st_size / (1024**3)  # Convert to GB
            existing[model_name] = f"✓ {info['file']} ({size:.2f}GB)"
            print(f"   ✓ {model_name}: {model_path}")
        else:
            existing[model_name] = "✗ Not found"
            print(f"   ✗ {model_name}: Not found")
    
    return existing

def display_options():
    """Display available models and their info"""
    print("\n🤖 Available Models:\n")
    
    for model_name, info in MODELS_INFO.items():
        recommend = "⭐ RECOMMENDED" if info["recommended"] else ""
        print(f"   {model_name.upper():12} | Size: {info['size']:6} | {info['note']}")
        print(f"   {' ' * 12} | {recommend}")
        print()

def create_directories():
    """Create required directories"""
    for model_name, info in MODELS_INFO.items():
        info["dir"].mkdir(parents=True, exist_ok=True)
    print("✓ Model directories created")

def download_model(model_name: str):
    """Download a model"""
    if model_name not in MODELS_INFO:
        print(f"✗ Unknown model: {model_name}")
        return False
    
    info = MODELS_INFO[model_name]
    model_path = info["dir"] / info["file"]
    
    if model_path.exists():
        print(f"✓ Model already exists: {model_path}")
        return True
    
    print(f"\n⬇️  Downloading {model_name.upper()}...")
    print(f"   From: {info['url']}")
    print(f"   To: {model_path}")
    print(f"   Size: {info['size']}")
    print("\n   NOTE: Manual Download Required!")
    print(f"   Please download from: {info['url']}")
    print(f"   And place the file at: {model_path}")
    print("\n   Why manual? The models are hosted on Hugging Face and")
    print("   require acceptance of license terms (which change per model).")
    print("   You'll need to:")
    print("   1. Visit the URL above")
    print("   2. Accept the model license")
    print("   3. Download the GGUF file")
    print("   4. Place it in the directory shown above")
    
    return False

def setup_config():
    """Create a config file for the models"""
    config = {
        "models_directory": str(MODELS_DIR),
        "default_model": "phi2",
        "models": {}
    }
    
    for model_name, info in MODELS_INFO.items():
        model_path = info["dir"] / info["file"]
        config["models"][model_name] = {
            "path": str(model_path),
            "file": info["file"],
            "size": info["size"],
            "ready": model_path.exists()
        }
    
    config_path = Path(__file__).parent / "models_config.json"
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"✓ Configuration saved to: {config_path}")
    return config_path

def main():
    print_banner()
    
    # Create directories
    print("📁 Setting up directories...")
    create_directories()
    
    # Check existing
    existing = check_existing_models()
    
    # Show options
    display_options()
    
    print("\n🔧 Setup Options:\n")
    print("   1. Download Phi-2 (RECOMMENDED)")
    print("   2. Download Mistral 7B")
    print("   3. Download TinyLLama")
    print("   4. View download instructions")
    print("   5. Skip (use current models)")
    print("   6. Exit")
    
    choice = input("\nEnter choice (1-6): ").strip()
    
    if choice == "1":
        download_model("phi2")
    elif choice == "2":
        download_model("mistral7b")
    elif choice == "3":
        download_model("tinyllama")
    elif choice == "4":
        for model_name, info in MODELS_INFO.items():
            print(f"\n{model_name.upper()}:")
            print(f"  URL: {info['url']}")
            print(f"  Size: {info['size']}")
    elif choice == "5":
        print("✓ Skipping downloads")
    elif choice == "6":
        print("Exiting...")
        return
    
    # Setup config
    print("\n⚙️  Creating configuration...")
    config_path = setup_config()
    
    print("\n" + "="*70)
    print("✓ Setup Complete!")
    print("="*70)
    print("\nNext Steps:")
    print("  1. If you selected a download option:")
    print("     - Follow the instructions provided")
    print("     - Download the model file")
    print("     - Place it in the appropriate directory")
    print("\n  2. Start the distributed IDS:")
    print("     docker-compose -f docker-compose-distributed.yml up -d")
    print("\n  3. Access the attack panel:")
    print("     http://localhost:7000")
    print("\nConfiguration file: " + str(config_path))
    print("\nFor more information, see: DEPLOYMENT_DISTRIBUTED.md")

if __name__ == "__main__":
    main()
