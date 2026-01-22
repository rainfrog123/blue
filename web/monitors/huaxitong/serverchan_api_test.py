#!/usr/bin/env python3
import requests
import json
from datetime import datetime

def test_serverchan():
    """Test Server酱 WeChat notification API"""
    
    # Server酱 URL (same as monitor script)
    url = "https://sctapi.ftqq.com/SCT282278T91zPNpvuek2817He3xtGpSLJ.send"
    
    # Test notification data
    data = {
        "title": "🔧 Server酱 API 测试",
        "desp": f"""## 📱 API 连接测试

**时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**状态**: 正在测试 Server酱 API 连接

### 测试详情:
- API 端点正常
- 微信推送服务连接中
- 预约监控系统就绪

---
💡 如收到此消息说明 Server酱 配置正确！""",
        "short": "API测试消息",
        "noip": "1"
    }
    
    try:
        print("📱 Testing Server酱 API...")
        response = requests.post(url, data=data, timeout=10)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Response: {json.dumps(result, indent=2, ensure_ascii=False)}")
            
            if result.get("errno") == 0:
                pushid = result.get("data", {}).get("pushid", "N/A")
                print(f"✅ Test notification sent! PushID: {pushid}")
            else:
                print(f"❌ Server酱 error: {result.get('message', 'Unknown')}")
        else:
            print(f"❌ HTTP error: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Test failed: {e}")

if __name__ == "__main__":
    test_serverchan()
