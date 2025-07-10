#!/usr/bin/env python3
"""
Simple System Test Script
"""

import time
import requests
import sys

def test_system():
    """Test if the SOC system is running properly"""
    print("🧪 Testing Advanced SOC Dashboard...")
    print("=" * 50)
    
    # Wait for server to start
    print("⏳ Waiting for server to start...")
    time.sleep(10)
    
    try:
        # Test system status
        print("🔍 Testing system status...")
        response = requests.get('http://localhost:5000/api/system/status', timeout=10)
        if response.status_code == 200:
            data = response.json()
            print("✅ System status working")
            print(f"   Status: {data.get('status', 'unknown')}")
        else:
            print(f"❌ System status failed: {response.status_code}")
            return False
        
        # Test model status
        print("🔍 Testing model status...")
        response = requests.get('http://localhost:5000/api/models/status', timeout=10)
        if response.status_code == 200:
            data = response.json()
            print("✅ Model status working")
            print(f"   Loaded models: {data.get('loaded_models', 0)}")
        else:
            print(f"❌ Model status failed: {response.status_code}")
            return False
        
        # Test dashboard stats
        print("🔍 Testing dashboard stats...")
        response = requests.get('http://localhost:5000/api/dashboard/stats', timeout=10)
        if response.status_code == 200:
            data = response.json()
            print("✅ Dashboard stats working")
            print(f"   Active threats: {data.get('active_threats', 0)}")
        else:
            print(f"❌ Dashboard stats failed: {response.status_code}")
            return False
        
        print("\n🎉 All tests passed! System is working correctly.")
        print("🌐 Dashboard is available at: http://localhost:5000")
        return True
        
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to server. Is it running?")
        print("💡 Try running: python app_advanced.py")
        return False
    except Exception as e:
        print(f"❌ Error testing system: {e}")
        return False

if __name__ == '__main__':
    success = test_system()
    sys.exit(0 if success else 1) 