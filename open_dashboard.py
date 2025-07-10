#!/usr/bin/env python3
"""
Open Dashboard in Browser
"""

import webbrowser
import time
import requests

def open_dashboard():
    """Open the dashboard in the default browser"""
    print("🌐 Opening Advanced SOC Dashboard...")
    print("=" * 50)
    
    # Wait a moment for server to be ready
    time.sleep(2)
    
    try:
        # Test if server is running
        response = requests.get('http://localhost:5000', timeout=5)
        if response.status_code == 200:
            print("✅ Server is running")
            print("🚀 Opening dashboard in browser...")
            
            # Open in default browser
            webbrowser.open('http://localhost:5000')
            
            print("\n🎉 Dashboard opened successfully!")
            print("📱 If the browser didn't open automatically, go to:")
            print("   http://localhost:5000")
            print()
            print("🔧 Dashboard Features Available:")
            print("   🤖 AI-Powered Threat Detection")
            print("   🔍 Real-time Monitoring")
            print("   📊 Advanced Analytics")
            print("   🛡️  Automated Response")
            print("   👤 UEBA Analysis")
            print("   ⚡ Live Updates")
            return True
        else:
            print(f"❌ Server not responding: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Server not running")
        print("💡 Start the server first with: python app_advanced.py")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == '__main__':
    success = open_dashboard()
    if not success:
        print("\n🔧 Troubleshooting:")
        print("1. Make sure the server is running: python app_advanced.py")
        print("2. Check if port 5000 is available")
        print("3. Try accessing manually: http://localhost:5000") 