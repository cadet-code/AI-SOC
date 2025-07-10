#!/usr/bin/env python3
"""
Simple Dependency Installation Script
Handles Python 3.12 compatibility issues
"""

import subprocess
import sys
import os

def install_package(package):
    """Install a single package with error handling"""
    try:
        print(f"Installing {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package, "--upgrade"])
        print(f"✅ {package} installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install {package}: {e}")
        return False

def main():
    """Install all required dependencies"""
    print("📦 Installing Dependencies for Advanced SOC Dashboard")
    print("=" * 60)
    
    # Core packages that should work with Python 3.12
    packages = [
        "Flask",
        "Flask-CORS", 
        "Flask-SocketIO",
        "python-socketio",
        "eventlet",
        "python-dotenv",
        "SQLAlchemy",
        "psutil",
        "plotly",
        "joblib",
        "scikit-learn",
        "pandas",
        "numpy"
    ]
    
    success_count = 0
    total_packages = len(packages)
    
    for package in packages:
        if install_package(package):
            success_count += 1
    
    print(f"\n📊 Installation Summary:")
    print(f"✅ Successfully installed: {success_count}/{total_packages}")
    print(f"❌ Failed installations: {total_packages - success_count}")
    
    if success_count >= total_packages * 0.8:  # At least 80% success
        print("\n🎉 Most dependencies installed successfully!")
        print("The system should work properly now.")
        return True
    else:
        print("\n⚠️  Some dependencies failed to install.")
        print("The system may have limited functionality.")
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1) 