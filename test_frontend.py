#!/usr/bin/env python3
"""
Test Frontend Accessibility
"""

import requests
import time

def test_frontend():
    """Test if the frontend is accessible"""
    print("🌐 Testing Frontend Accessibility...")
    print("=" * 50)
    
    try:
        # Test the main page
        print("🔍 Testing main dashboard page...")
        response = requests.get('http://localhost:5000', timeout=10)
        
        if response.status_code == 200:
            print("✅ Main page is accessible")
            
            # Check if it contains the dashboard title
            if "Advanced AI-Driven SOC Dashboard" in response.text:
                print("✅ Dashboard title found in page")
            else:
                print("⚠️  Dashboard title not found in page")
                
            # Check for key elements
            if "socket.io" in response.text.lower():
                print("✅ WebSocket support detected")
            else:
                print("⚠️  WebSocket support not detected")
                
            if "chart.js" in response.text.lower():
                print("✅ Chart.js support detected")
            else:
                print("⚠️  Chart.js support not detected")
                
            print(f"\n📊 Page size: {len(response.text)} characters")
            print("🌐 Dashboard is ready at: http://localhost:5000")
            return True
        else:
            print(f"❌ Main page failed: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to server")
        print("💡 Make sure the server is running with: python app_advanced.py")
        return False
    except Exception as e:
        print(f"❌ Error testing frontend: {e}")
        return False

if __name__ == '__main__':
    success = test_frontend()
    if success:
        print("\n🎉 Frontend is working correctly!")
        print("📱 Open your browser and go to: http://localhost:5000")
    else:
        print("\n❌ Frontend test failed")
        print("🔧 Check the server logs for errors") 