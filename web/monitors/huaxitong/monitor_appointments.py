#!/usr/bin/env python3
import requests
import json
import time
import os
import sys
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any

class AppointmentMonitor:
    def __init__(self):
        self.url = "https://hytapiv2.cd120.com/cloud/appointment/doctorListModel/selDoctorDetailsTwo"
        self.headers = {
            "Host": "hytapiv2.cd120.com",
            "UUID": "25FEFB37-9D3D-4FA1-B7E8-81F7FB0A2FAD",
            "Mac": "Not Found",
            "Accept": "*/*",
            "Client-Version": "7.1.1",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-GB;q=1",
            "token": "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIyNzkwODA5NTBiOWY4NzhlNjcwZTg3Y2VjOWYwNzc5YmI5ODE0NTVhZDM3YmUyMjViZjVkODkzODA4MTM5YzYwMDgwODBhIiwiaWF0IjoxNzYyMjUyMDE4LCJzdWIiOiJ7XCJ1c2VySWRcIjpcIjI3OTA4MFwiLFwiYWNjb3VudElkXCI6XCIyOTMzNjBcIixcInVzZXJUeXBlXCI6MCxcImFwcENvZGVcIjpcIkhYR1lBUFBcIixcImNoYW5uZWxDb2RlXCI6XCJQQVRJRU5UX0lPU1wiLFwiZGV2aWNlbnVtYmVyXCI6XCI5NTBiOWY4NzhlNjcwZTg3Y2VjOWYwNzc5YmI5ODE0NTVhZDM3YmUyMjViZjVkODkzODA4MTM5YzYwMDgwODBhXCIsXCJkZXZpY2VUeXBlXCI6XCJBUFBcIixcImFjY291bnROb1wiOlwiMTM4ODI5ODUxODhcIixcIm5hbWVcIjpcIumZiOS6leW3nVwiLFwiZG9jdG9ySWRcIjpudWxsLFwib3JnYW5Db2RlXCI6bnVsbH0iLCJleHAiOjE3NjQ4NDQwMTh9.uJjbbfjVPJ9s-gxmSyE94sPkiCoUMRm500ZNACnIov4***HXGYAPP",
            "accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIyNzkwODA5NTBiOWY4NzhlNjcwZTg3Y2VjOWYwNzc5YmI5ODE0NTVhZDM3YmUyMjViZjVkODkzODA4MTM5YzYwMDgwODBhIiwiaWF0IjoxNzYyMjUyMDE4LCJzdWIiOiJ7XCJ1c2VySWRcIjpcIjI3OTA4MFwiLFwiYWNjb3VudElkXCI6XCIyOTMzNjBcIixcInVzZXJUeXBlXCI6MCxcImFwcENvZGVcIjpcIkhYR1lBUFBcIixcImNoYW5uZWxDb2RlXCI6XCJQQVRJRU5UX0lPU1wiLFwiZGV2aWNlbnVtYmVyXCI6XCI5NTBiOWY4NzhlNjcwZTg3Y2VjOWYwNzc5YmI5ODE0NTVhZDM3YmUyMjViZjVkODkzODA4MTM5YzYwMDgwODBhXCIsXCJkZXZpY2VUeXBlXCI6XCJBUFBcIixcImFjY291bnROb1wiOlwiMTM4ODI5ODUxODhcIixcIm5hbWVcIjpcIumZiOS6leW3nVwiLFwiZG9jdG9ySWRcIjpudWxsLFwib3JnYW5Db2RlXCI6bnVsbH0iLCJleHAiOjE3NjQ4NDQwMTh9.uJjbbfjVPJ9s-gxmSyE94sPkiCoUMRm500ZNACnIov4***HXGYAPP",
            "Content-Type": "application/json",
            "User-Agent": "hua yi tong/7.1.1 (iPhone; iOS 15.7.1; Scale/3.00)",
            "Connection": "keep-alive",
            "Cookie": "acw_tc=1a0c39d517622521666711325e1d4a38b46413dac72c7dd846be940d0c3d7e"
        }
        
        # Doctor to monitor
        self.doctors = [
            {
                "name": "唐新 (肩肘运动医学/微创)",
                "payload": {
                    "hospitalCode": "HID0101",
                    "deptCode": "",
                    "doctorId": "4028b88164b5af330164b5af33e10001",
                    "channelCode": "PATIENT_IOS",
                    "appCode": "HXGYAPP",
                    "hospitalAreaCode": "",
                    "tabAreaCode": "",
                    "cardId": "",
                    "encrypt": "enKQHUmF2Yeelk1t6dArBg==",
                    "deptCategoryCode": "",
                    "appointmentType": "1"
                }
            }
        ]
        
        
        # Dynamic user agent generation data
        self.app_versions = [
            "7.0.8", "7.0.9", "7.1.0", "7.1.1", "7.1.2", "7.2.0"
        ]
        self.ios_versions = [
            "15.6.1", "15.7.0", "15.7.1", "15.7.2", "15.7.3", "15.7.4", "15.7.5", "15.7.6", "15.7.7", "15.7.8", "15.7.9", "15.8.0", "15.8.1", "15.8.2",
            "16.0.0", "16.0.1", "16.0.2", "16.0.3", "16.1.0", "16.1.1", "16.1.2", "16.2.0", "16.3.0", "16.3.1", "16.4.0", "16.4.1", "16.5.0", "16.5.1", "16.6.0", "16.6.1", "16.7.0", "16.7.1", "16.7.2"
        ]
        self.device_models = [
            "iPhone13,1", "iPhone13,2", "iPhone13,3", "iPhone13,4",  # iPhone 12 series
            "iPhone14,2", "iPhone14,3", "iPhone14,4", "iPhone14,5",  # iPhone 13 series  
            "iPhone14,7", "iPhone14,8",  # iPhone 13 mini/Pro Max
            "iPhone12,1", "iPhone12,3", "iPhone12,5", "iPhone12,8",  # iPhone 11 series
            "iPhone11,2", "iPhone11,4", "iPhone11,6", "iPhone11,8",  # iPhone XS series
        ]
        self.scale_values = ["2.00", "3.00"]
        
        # Track previous state of remaining numbers for each doctor
        self.previous_remaining = {}
        
        # 中国标准时间 CST (UTC+8) 
        self.cst_tz = timezone(timedelta(hours=8))
        
        # Server酱通知配置
        self.serverchan_url = "https://sctapi.ftqq.com/SCT282278T91zPNpvuek2817He3xtGpSLJ.send"
        self.last_notification_time = 0  # Track last notification timestamp
        self.notification_cooldown = 300  # 5 minutes in seconds
        
    def get_current_payload(self, doctor_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Generate payload with current timestamp for specific doctor"""
        payload = doctor_payload.copy()
        # Use current timestamp (Unix timestamp as string)
        payload["timestamp"] = str(int(time.time()))
        return payload
    
    def generate_random_user_agent(self) -> str:
        """Generate a completely random but realistic User-Agent"""
        app_version = random.choice(self.app_versions)
        device_model = random.choice(self.device_models)
        ios_version = random.choice(self.ios_versions)
        scale = random.choice(self.scale_values)
        
        return f"hua yi tong/{app_version} ({device_model}; iOS {ios_version}; Scale/{scale})"
    
    def generate_random_uuid(self) -> str:
        """Generate a completely random UUID"""
        return str(uuid.uuid4()).upper()
    
    def get_randomized_headers(self) -> Dict[str, str]:
        """Get headers with completely randomized User-Agent and UUID"""
        headers = self.headers.copy()
        # Generate completely random User-Agent
        headers["User-Agent"] = self.generate_random_user_agent()
        # Generate completely random UUID
        headers["UUID"] = self.generate_random_uuid()
        return headers
    
    def is_peak_hour(self) -> bool:
        """Check if current time is within peak monitoring windows (7:59-8:04 AM/PM 中国时间)"""
        now_cst = datetime.now(self.cst_tz)
        current_time = now_cst.time()
        
        # Define peak windows: 7:59:00 - 8:04:00 AM and PM (5 minutes each)
        morning_start = datetime.strptime("07:59:00", "%H:%M:%S").time()
        morning_end = datetime.strptime("08:04:00", "%H:%M:%S").time()
        evening_start = datetime.strptime("19:59:00", "%H:%M:%S").time()
        evening_end = datetime.strptime("20:04:00", "%H:%M:%S").time()
        
        is_morning_peak = morning_start <= current_time <= morning_end
        is_evening_peak = evening_start <= current_time <= evening_end
        
        return is_morning_peak or is_evening_peak
    
    def get_wait_time(self) -> float:
        """Get appropriate wait time based on current time"""
        if self.is_peak_hour():
            return 5.0  # 5 seconds during peak hours
        else:
            return random.uniform(15, 25)  # 15-25 seconds normally
    
    def send_request(self, doctor_payload: Dict[str, Any], doctor_name: str) -> Dict[str, Any]:
        """Send the API request and return the response for specific doctor"""
        try:
            # Add small random delay before request (0.5-2 seconds)
            time.sleep(random.uniform(0.5, 2.0))
            
            # Get dynamic payload and headers
            payload = self.get_current_payload(doctor_payload)
            headers = self.get_randomized_headers()
            
            response = requests.post(self.url, headers=headers, json=payload, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"❌ HTTP {response.status_code}: {response.text[:100]}...")
                return None
        except requests.exceptions.RequestException as e:
            print(f"Request error for {doctor_name}: {e}")
            return None
    
    def get_time_period_label(self, schedule_range: int) -> str:
        """Get time period label based on scheduleRange"""
        if schedule_range == 0:
            return "上午"
        elif schedule_range == 1:
            return "下午"
        else:
            return f"时段{schedule_range}"
    
    def extract_remaining_numbers(self, data: Dict[str, Any], doctor_name: str) -> List[Dict[str, Any]]:
        """Extract all appointment entries from the response"""
        if not data or data.get("code") != "1":
            return []
            
        entries = []
        seen_ids = set()
        
        def add_entry(item):
            schedule_id = item.get("sysScheduleId")
            if schedule_id and schedule_id not in seen_ids:
                seen_ids.add(schedule_id)
                schedule_range = item.get("scheduleRange", 0)
                entries.append({
                    "id": schedule_id,
                    "scheduleDate": item.get("scheduleDate"),
                    "scheduleRange": schedule_range,
                    "timePeriod": self.get_time_period_label(schedule_range),
                    "remainingNum": item.get("remainingNum", 0),
                    "availableCount": item.get("availableCount", 0),
                    "status": item.get("status", 0),
                    "deptName": item.get("deptName"),
                    "hospitalAreaName": item.get("hospitalAreaName"),
                    "dayDesc": item.get("dayDesc"),
                    "admLocation": item.get("admLocation"),
                    "regFee": item.get("regFee", 0),
                    "serviceFee": item.get("serviceFee", 0),
                    "regTitelName": item.get("regTitelName", "")
                })
        
        response_data = data.get("data", {})
        
        # Process flat list
        for item in response_data.get("sourceItemsRespVos", []) or []:
            add_entry(item)
        
        # Process nested structure
        for area in response_data.get("sourceItems", []) or []:
            if area:
                for item in area.get("sourceItemsRespVos", []) or []:
                    add_entry(item)
        
        return entries
    
    def check_for_changes(self, current_entries: List[Dict[str, Any]], doctor_name: str) -> List[Dict[str, Any]]:
        """Check for appointments that changed: availableCount (0→positive) or status (0/2约满/3停诊→1可约)"""
        changes = []
        
        for entry in current_entries:
            entry_id = entry["id"]
            changed_fields = []
            
            # Track availableCount: 0 → positive
            avail_key = f"{doctor_name}_{entry_id}_avail"
            prev_avail = self.previous_remaining.get(avail_key, 0)
            curr_avail = entry["availableCount"]
            
            if prev_avail == 0 and curr_avail > 0:
                changed_fields.append(f"availableCount: {prev_avail} → {curr_avail}")
            self.previous_remaining[avail_key] = curr_avail
            
            # Track status: any (0,2约满,3停诊) → 1可约
            status_key = f"{doctor_name}_{entry_id}_status"
            prev_status = self.previous_remaining.get(status_key, -1)
            curr_status = entry["status"]
            
            if prev_status >= 0 and curr_status == 1 and prev_status != 1:
                changed_fields.append(f"status: {prev_status} → {curr_status}")
            self.previous_remaining[status_key] = curr_status
            
            # Add to changes if anything changed
            if changed_fields:
                change_info = entry.copy()
                change_info["changes_summary"] = ", ".join(changed_fields)
                changes.append(change_info)
        
        return changes
    
    def notify_user(self, changes: List[Dict[str, Any]]):
        """Notify user about available appointments"""
        print(f"\n🎉 APPOINTMENT SLOTS AVAILABLE! 🎉")
        print(f"Time: {datetime.now(self.cst_tz).strftime('%Y-%m-%d %H:%M:%S CST')}")
        print(f"Found {len(changes)} new available slot(s):")
        
        # Group by doctor for display
        changes_by_doctor = {}
        for change in changes:
            doctor_name = change.get("doctor_name", "Unknown")
            if doctor_name not in changes_by_doctor:
                changes_by_doctor[doctor_name] = []
            changes_by_doctor[doctor_name].append(change)
        
        slot_counter = 1
        for doctor_name, doctor_changes in changes_by_doctor.items():
            print(f"\n  👨‍⚕️ {doctor_name}:")
            for change in doctor_changes:
                reg_fee = change.get("regFee", 0)
                service_fee = change.get("serviceFee", 0)
                total_fee = reg_fee + service_fee
                reg_title = change.get("regTitelName", "")
                
                print(f"    Slot {slot_counter}:")
                print(f"      📅 Date: {change['scheduleDate']} {change['timePeriod']} ({change['dayDesc']})")
                print(f"      🏥 Department: {change['deptName']}")
                print(f"      📍 Location: {change['admLocation']}")
                print(f"      🏢 Hospital Area: {change['hospitalAreaName']}")
                print(f"      💰 Fee: ¥{reg_fee} + ¥{service_fee} = ¥{total_fee} ({reg_title})")
                print(f"      🔢 Available: {change.get('availableCount', 0)} slots")
                print(f"      🔄 Changes: {change['changes_summary']}")
                slot_counter += 1
        
        print("="*60)
        
        # Send Server酱 WeChat notification
        self.send_serverchan_notification(changes)
        
        # Try to send system notification (if available)
        try:
            doctors_list = ", ".join(set(c.get("doctor_name", "Unknown") for c in changes))
            os.system(f'notify-send "Appointment Available" "{len(changes)} new slot(s) found for {doctors_list}"')
        except:
            pass  # Ignore if notify-send is not available
    
    def send_serverchan_notification(self, changes: List[Dict[str, Any]]):
        """Send WeChat notification via Server酱 (with 5-minute cooldown)"""
        try:
            # Check cooldown period
            current_time = time.time()
            time_since_last = current_time - self.last_notification_time
            
            if time_since_last < self.notification_cooldown:
                remaining_cooldown = self.notification_cooldown - time_since_last
                print(f"📱 Notification cooldown: {remaining_cooldown:.0f}s remaining (preventing spam)")
                return
            # Prepare notification content
            title = f"🎉 预约成功监控 - 发现{len(changes)}个空位!"
            
            # Group changes by doctor
            changes_by_doctor = {}
            for change in changes:
                doctor_name = change.get("doctor_name", "Unknown")
                if doctor_name not in changes_by_doctor:
                    changes_by_doctor[doctor_name] = []
                changes_by_doctor[doctor_name].append(change)
            
            doctors_list = ", ".join(changes_by_doctor.keys())
            
            # Build detailed message content in Markdown
            desp_lines = [
                f"## 📅 预约信息",
                f"**医生**: {doctors_list}",
                f"**时间**: {datetime.now(self.cst_tz).strftime('%Y-%m-%d %H:%M:%S CST')}",
                f"**发现**: {len(changes)} 个可预约时段",
                "",
                "### 📋 可预约时段详情:"
            ]
            
            slot_counter = 1
            for doctor_name, doctor_changes in changes_by_doctor.items():
                desp_lines.extend([
                    f"",
                    f"### 👨‍⚕️ {doctor_name}"
                ])
                
                for change in doctor_changes:
                    # Get actual fee information from the data
                    reg_fee = change.get("regFee", 0)
                    service_fee = change.get("serviceFee", 0)
                    total_fee = reg_fee + service_fee
                    reg_title = change.get("regTitelName", "")
                    fee_info = f"挂号费{reg_fee}元 + 服务费{service_fee}元 = 总计{total_fee}元 ({reg_title})"
                    
                    desp_lines.extend([
                        f"",
                        f"**时段 {slot_counter}:**",
                        f"- 📅 日期: {change['scheduleDate']} {change['timePeriod']} ({change['dayDesc']})",
                        f"- 🏥 科室: {change['deptName']}",
                        f"- 📍 地点: {change['admLocation']}",
                        f"- 🏢 院区: {change['hospitalAreaName']}",
                        f"- 💰 费用: {fee_info}",
                        f"- 🔢 可预约数: {change.get('availableCount', 0)}",
                        f"- 🔄 变化: {change['changes_summary']}"
                    ])
                    slot_counter += 1
            
            desp_lines.extend([
                "",
                "---",
                f"💡 **提醒**: 请尽快登录华西医院App进行预约！"
            ])
            
            desp = "\n".join(desp_lines)
            
            # Prepare notification data
            notification_data = {
                "title": title,
                "desp": desp,
                "short": f"发现{len(changes)}个预约时段 - {changes[0]['scheduleDate']} {changes[0]['timePeriod']}",
                "noip": "1"  # Hide IP for privacy
            }
            
            print(f"📱 Sending WeChat notification via Server酱...")
            
            # Send POST request
            response = requests.post(self.serverchan_url, data=notification_data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get("errno") == 0:
                    pushid = result.get("data", {}).get("pushid", "N/A")
                    print(f"✅ WeChat notification sent successfully! PushID: {pushid}")
                    # Update last notification time
                    self.last_notification_time = current_time
                else:
                    print(f"❌ Server酱 error: {result.get('message', 'Unknown error')}")
            else:
                print(f"❌ HTTP error: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Failed to send WeChat notification: {e}")
    
    def run_monitor(self):
        """Main monitoring loop"""
        print(f"🔍 Starting appointment monitor...")
        print(f"⏰ Normal: 15-25s intervals | Peak: 5s intervals (7:59-8:04 AM/PM 中国时间)")
        print(f"🎯 Monitoring: 唐新 (肩肘运动医学/微创)")
        print(f"🛡️ Anti-detection: Dynamic timestamps, randomized intervals, rotating User-Agents")
        print(f"📱 WeChat notifications: Enabled via Server酱")
        print(f"🔍 Tracking: availableCount (0→positive), status (0/2约满/3停诊→1可约), time periods (上午/下午)")
        print("="*60)
        
        iteration = 0
        while True:
            try:
                iteration += 1
                timestamp = datetime.now(self.cst_tz).strftime("%Y-%m-%d %H:%M:%S CST")
                
                print(f"[{timestamp}] Check #{iteration}")
                
                all_changes = []
                all_entries = []
                
                # Check doctor
                doctor = self.doctors[0]
                doctor_name = doctor["name"]
                response_data = self.send_request(doctor["payload"], doctor_name)
                
                if response_data:
                    current_entries = self.extract_remaining_numbers(response_data, doctor_name)
                    
                    if current_entries:
                        # Add doctor name to entries
                        for entry in current_entries:
                            entry["doctor_name"] = doctor_name
                        all_entries = current_entries
                        
                        # Check for changes
                        changes = self.check_for_changes(current_entries, doctor_name)
                        if changes:
                            for change in changes:
                                change["doctor_name"] = doctor_name
                            all_changes = changes
                        
                        # Display summary
                        total_avail = sum(e["availableCount"] for e in current_entries)
                        status_1_count = sum(1 for e in current_entries if e["status"] == 1)
                        print(f"✓ {total_avail} slots, {status_1_count} bookable (status=1)")
                        
                        # Show slot details
                        for entry in current_entries:
                            status_map = {1: "可约", 2: "约满", 3: "停诊"}
                            status_label = status_map.get(entry["status"], f"状态{entry['status']}")
                            fee = entry["regFee"] + entry["serviceFee"]
                            print(f"  • {entry['scheduleDate']} {entry['timePeriod']} | "
                                  f"{entry['hospitalAreaName']} | {entry['deptName']} | "
                                  f"可约:{entry['availableCount']} | ¥{fee} | {status_label}")
                    else:
                        print(f"⚠ No appointment data")
                else:
                    print(f"❌ Failed to get response")
                
                # Notify if changes found
                if all_changes:
                    self.notify_user(all_changes)
                
                # Get appropriate wait time based on current time
                wait_time = self.get_wait_time()
                is_peak = self.is_peak_hour()
                peak_status = "🔥 PEAK HOUR" if is_peak else "⏳ Normal"
                print(f"[{timestamp}] {peak_status} - Waiting {wait_time:.1f} seconds until next check...")
                time.sleep(wait_time)
                
            except KeyboardInterrupt:
                stop_time_cst = datetime.now(self.cst_tz).strftime('%Y-%m-%d %H:%M:%S CST')
                print(f"\n\n⏹️  Monitor stopped by user at {stop_time_cst}")
                break
            except Exception as e:
                error_time = datetime.now(self.cst_tz).strftime('%Y-%m-%d %H:%M:%S CST')
                print(f"[{error_time}] Error: {e}")
                # Random wait on error too
                error_wait = random.uniform(30, 60)
                print(f"[{error_time}] Waiting {error_wait:.1f} seconds before retry...")
                time.sleep(error_wait)

if __name__ == "__main__":
    monitor = AppointmentMonitor()
    monitor.run_monitor() 