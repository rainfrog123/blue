#!/usr/bin/env python3
"""
Stomatology Appointment Monitor
Monitors available slots for all doctors in the stomatology department with Server Chan notifications
"""

import aiohttp
import asyncio
import json
import time
import os
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

class StomatologyMonitor:
    def __init__(self):
        self.base_url = "https://uf-wechat.scgh114.com"
        self.headers = {
            'Host': 'uf-wechat.scgh114.com',
            'Connection': 'keep-alive',
            'token': '',
            'content-type': 'application/json',
            'Accept-Encoding': 'gzip,compress,br,deflate',
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.61(0x18003d2b) NetType/WIFI Language/en',
            'Referer': 'https://servicewechat.com/wx0f0dbe95c1397ee9/164/page-frame.html'
        }
        
        # Department configuration - default to Periodontal Disease (牙周病科)
        self.department_id = 7301
        self.department_name = "牙周病科（华西院区）"
        
        # Server Chan configuration
        self.serverchan_url = "https://sctapi.ftqq.com/SCT282278TOxQRSjkfr6zTL0r7gQTi4wyZ.send"
        self.last_notification_time = 0
        self.notification_cooldown = 300  # 5 minutes
        self.notification_lock = asyncio.Lock()  # Prevent race conditions
        
        # Timezone configuration
        self.cst_tz = timezone(timedelta(hours=8))
        
        # Monitoring configuration
        self.check_interval = 20  # Check every 20 seconds
        
        # Logging configuration
        self.log_file = "stomatology_success.log"
        self.reg_log_file = "stomatology_reg.log"
        
        # Doctor IDs storage
        self.doctor_ids = {}
        
        # Initialize log files
        self.init_logs()
        
    def init_logs(self):
        """Initialize log files"""
        # Create log files if they don't exist, but don't clear existing content
        start_time = datetime.now(self.cst_tz).strftime('%Y-%m-%d %H:%M:%S CST')
        
        # Add session start marker to existing logs
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"[{start_time}] 🚀 New monitoring session started\n")
            f.write(f"{'='*60}\n")
        
        with open(self.reg_log_file, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"[{start_time}] 🚀 New monitoring session started\n")
            f.write(f"{'='*60}\n")
    
    def get_date_range(self, start_date: str, days: int = 7) -> List[str]:
        """Generate list of dates for the next 'days' days"""
        start = datetime.strptime(start_date, '%Y-%m-%d')
        dates = []
        
        for i in range(days):
            current_date = start + timedelta(days=i)
            dates.append(current_date.strftime('%Y-%m-%d'))
            
        return dates
    
    async def get_doctor_list(self, session: aiohttp.ClientSession, date: str) -> List[Dict[str, Any]]:
        """Get list of doctors for a specific date"""
        url = f"{self.base_url}/doctor/findDoctorList.web"
        params = {
            'rosterIsNull': 1,
            'pageIndex': 0,
            'pageSize': 20,
            'date': date,
            'professional': '',
            'zn': 1,
            'realAreaCode': '',
            'departmentId': self.department_id,
            'tokenData': ''
        }
        
        try:
            async with session.get(url, params=params, headers=self.headers) as response:
                response.raise_for_status()
                
                data = await response.json()
                if data.get('code') == 1 and 'data' in data:
                    return data['data'].get('content', [])
                else:
                    return []
                    
        except aiohttp.ClientError as e:
            print(f"Request error getting doctor list for {date}: {e}")
            return []
        except json.JSONDecodeError as e:
            print(f"JSON decode error for {date}: {e}")
            return []
    
    async def get_doctor_roster(self, session: aiohttp.ClientSession, doctor_id: int) -> Dict[str, Any]:
        """Get detailed roster information for a specific doctor"""
        url = f"{self.base_url}/dutyRoster/findByRoster.web"
        params = {
            'doctorId': doctor_id
        }
        
        try:
            async with session.get(url, params=params, headers=self.headers) as response:
                response.raise_for_status()
                
                data = await response.json()
                if data.get('code') == 1:
                    return {
                        'doctor_id': doctor_id,
                        'success': True,
                        'roster_data': data.get('data', []),
                        'timestamp': data.get('timestamp')
                    }
                else:
                    return {
                        'doctor_id': doctor_id,
                        'success': False,
                        'error': data.get('msg', 'Unknown error'),
                        'roster_data': []
                    }
                    
        except aiohttp.ClientError as e:
            return {
                'doctor_id': doctor_id,
                'success': False,
                'error': str(e),
                'roster_data': []
            }
        except json.JSONDecodeError as e:
            return {
                'doctor_id': doctor_id,
                'success': False,
                'error': f"JSON decode error: {e}",
                'roster_data': []
            }
    
    async def collect_all_doctor_ids(self) -> Dict[int, Dict[str, Any]]:
        """Collect all doctor IDs from the next 7 days"""
        print(f"🔍 Collecting all doctor IDs for {self.department_name}...")
        
        start_date = datetime.now().strftime('%Y-%m-%d')
        dates = self.get_date_range(start_date, 7)
        all_doctors = {}
        
        async with aiohttp.ClientSession() as session:
            # Create tasks for concurrent requests
            tasks = []
            for date in dates:
                print(f"📅 Preparing to get doctor list for {date}...")
                tasks.append(self.get_doctor_list(session, date))
            
            # Execute all requests concurrently
            print(f"🚀 Making concurrent requests for {len(dates)} dates...")
            results = await asyncio.gather(*tasks)
            
            # Process results
            for i, doctors in enumerate(results):
                date = dates[i]
                print(f"📅 Processing {len(doctors)} doctors for {date}...")
                
                for doctor in doctors:
                    if doctor['id'] not in all_doctors:
                        all_doctors[doctor['id']] = {
                            'id': doctor['id'],
                            'name': doctor['name'],
                            'jobTitle': doctor['jobTitle'],
                            'departmentName': doctor['departmentName'],
                            'appointmentCount': doctor['appointmentCount'],
                            'star': doctor['star']
                        }
        
        print(f"📊 Found {len(all_doctors)} unique doctors")
        return all_doctors
    
    async def check_doctor_availability(self, session: aiohttp.ClientSession, doctor_id: int, doctor_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check availability for a specific doctor"""
        roster_result = await self.get_doctor_roster(session, doctor_id)
        
        if not roster_result['success']:
            return []
        
        available_slots = []
        for slot in roster_result['roster_data']:
            if slot.get('remainingNumber', 0) > 0:
                available_slots.append({
                    'doctor_id': doctor_id,
                    'doctor_name': doctor_info['name'],
                    'doctor_title': doctor_info['jobTitle'],
                    'slot_id': slot['id'],
                    'date': slot['date'],
                    'dayOfWeek': slot['dayOfWeek'],
                    'timeInterval': slot['timeInterval'],
                    'totalNumber': slot['totalNumber'],
                    'remainingNumber': slot['remainingNumber'],
                    'appointmentAmount': slot['appointmentAmount'],
                    'timestamp': datetime.now(self.cst_tz).strftime('%Y-%m-%d %H:%M:%S CST')
                })
        
        return available_slots
    
    def log_success(self, available_slots: List[Dict[str, Any]]):
        """Log successful findings to file"""
        timestamp = datetime.now(self.cst_tz).strftime('%Y-%m-%d %H:%M:%S CST')
        
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] Found {len(available_slots)} available slots:\n")
            for slot in available_slots:
                f.write(f"  - Dr. {slot['doctor_name']} ({slot['doctor_title']}): {slot['date']} {slot['dayOfWeek']} {slot['timeInterval']} - {slot['remainingNumber']}/{slot['totalNumber']} slots - ¥{slot['appointmentAmount']}\n")
            f.write("\n")
    
    def log_regular_check(self, total_doctors: int, total_slots: int):
        """Log regular check to file"""
        timestamp = datetime.now(self.cst_tz).strftime('%Y-%m-%d %H:%M:%S CST')
        
        with open(self.reg_log_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] Checked {total_doctors} doctors, {total_slots} total slots, 0 available\n")
    
    async def send_serverchan_notification(self, available_slots: List[Dict[str, Any]]):
        """Send WeChat notification via Server Chan"""
        # Use async lock to prevent race conditions
        async with self.notification_lock:
            try:
                # Check cooldown period
                current_time = time.time()
                time_since_last = current_time - self.last_notification_time
                
                if time_since_last < self.notification_cooldown:
                    remaining_cooldown = self.notification_cooldown - time_since_last
                    print(f"📱 Notification cooldown: {remaining_cooldown:.0f}s remaining (preventing spam)")
                    # Log the blocked notification
                    timestamp = datetime.now(self.cst_tz).strftime('%Y-%m-%d %H:%M:%S CST')
                    with open(self.log_file, "a", encoding="utf-8") as f:
                        f.write(f"[{timestamp}] Notification blocked by cooldown - {remaining_cooldown:.0f}s remaining\n")
                    return
                
                # Set cooldown timestamp BEFORE sending (prevent race condition)
                self.last_notification_time = current_time
                print(f"📱 Cooldown updated - next notification allowed after {datetime.fromtimestamp(current_time + self.notification_cooldown).strftime('%H:%M:%S')}")
                
                # Prepare notification content
                title = f"🦷 口腔科预约 - 发现{len(available_slots)}个空位!"
                
                # Group slots by doctor
                slots_by_doctor = {}
                for slot in available_slots:
                    doctor_name = slot['doctor_name']
                    if doctor_name not in slots_by_doctor:
                        slots_by_doctor[doctor_name] = []
                    slots_by_doctor[doctor_name].append(slot)
                
                doctors_list = ", ".join(slots_by_doctor.keys())
                
                # Build detailed message content in Markdown
                desp_lines = [
                    f"## 🦷 {self.department_name} 预约信息",
                    f"**医生**: {doctors_list}",
                    f"**时间**: {datetime.now(self.cst_tz).strftime('%Y-%m-%d %H:%M:%S CST')}",
                    f"**发现**: {len(available_slots)} 个可预约时段",
                    "",
                    "### 📋 可预约时段详情:"
                ]
                
                slot_counter = 1
                for doctor_name, doctor_slots in slots_by_doctor.items():
                    doctor_title = doctor_slots[0]['doctor_title']
                    desp_lines.extend([
                        f"",
                        f"### 👨‍⚕️ {doctor_name} ({doctor_title})"
                    ])
                    
                    for slot in doctor_slots:
                        desp_lines.extend([
                            f"",
                            f"**时段 {slot_counter}:**",
                            f"- 📅 日期: {slot['date']} {slot['timeInterval']} ({slot['dayOfWeek']})",
                            f"- 🏥 科室: {self.department_name}",
                            f"- 🔄 可预约: {slot['remainingNumber']}/{slot['totalNumber']} 个名额",
                            f"- 💰 费用: ¥{slot['appointmentAmount']}",
                            f"- 🆔 时段ID: {slot['slot_id']}"
                        ])
                        slot_counter += 1
                
                desp_lines.extend([
                    "",
                    "---",
                    f"💡 **提醒**: 请尽快登录华西口腔医院系统进行预约！",
                    f"🔗 **监控日志**: {self.log_file}",
                    f"🌐 **预约网址**: {self.base_url}"
                ])
                
                desp = "\n".join(desp_lines)
                
                # Prepare notification data
                notification_data = {
                    "title": title,
                    "desp": desp,
                    "short": f"发现{len(available_slots)}个预约时段 - {available_slots[0]['doctor_name']} {available_slots[0]['date']} {available_slots[0]['timeInterval']}",
                    "noip": "1"  # Hide IP for privacy
                }
                
                print(f"📱 Sending WeChat notification via Server Chan...")
                
                # Send POST request
                async with aiohttp.ClientSession() as session:
                    async with session.post(self.serverchan_url, data=notification_data, timeout=10) as response:
                        if response.status == 200:
                            result = await response.json()
                            if result.get("errno") == 0:
                                pushid = result.get("data", {}).get("pushid", "N/A")
                                print(f"✅ WeChat notification sent successfully! PushID: {pushid}")
                                # Cooldown timestamp was already set before sending
                            else:
                                print(f"❌ Server Chan error: {result.get('message', 'Unknown error')}")
                                # Reset cooldown if notification failed
                                self.last_notification_time = 0
                                print(f"🔄 Cooldown reset due to notification failure")
                        else:
                            print(f"❌ HTTP error: {response.status}")
                            # Reset cooldown if HTTP request failed
                            self.last_notification_time = 0
                            print(f"🔄 Cooldown reset due to HTTP error")
                    
            except Exception as e:
                print(f"❌ Failed to send WeChat notification: {e}")
                # Reset cooldown if exception occurred
                self.last_notification_time = 0
                print(f"🔄 Cooldown reset due to exception")
    
    async def notify_user(self, available_slots: List[Dict[str, Any]]):
        """Send notifications to user"""
        if not available_slots:
            return
        
        # Log the findings
        self.log_success(available_slots)
        
        # Send Server Chan WeChat notification
        await self.send_serverchan_notification(available_slots)
        
        # Print to console
        print(f"🎉 FOUND {len(available_slots)} AVAILABLE SLOTS!")
        for slot in available_slots:
            print(f"   👨‍⚕️ Dr. {slot['doctor_name']} ({slot['doctor_title']})")
            print(f"   📅 {slot['date']} {slot['dayOfWeek']} {slot['timeInterval']}")
            print(f"   🎯 {slot['remainingNumber']}/{slot['totalNumber']} slots - ¥{slot['appointmentAmount']}")
            print(f"   🆔 Slot ID: {slot['slot_id']}")
            print()
    
    async def run_monitor(self):
        """Main monitoring loop"""
        print(f"🦷 Starting Stomatology Appointment Monitor...")
        print(f"🏥 Department: {self.department_name}")
        print(f"📋 Success logging to: {self.log_file}")
        print(f"📝 Regular logging to: {self.reg_log_file}")
        print(f"⏰ Check interval: {self.check_interval} seconds")
        print(f"📱 WeChat notifications: Enabled via Server Chan")
        print(f"🛡️ Notification cooldown: {self.notification_cooldown} seconds")
        
        # Initial collection of all doctor IDs
        self.doctor_ids = await self.collect_all_doctor_ids()
        
        if not self.doctor_ids:
            print("❌ No doctors found! Exiting...")
            return
        
        print(f"🎯 Monitoring {len(self.doctor_ids)} doctors:")
        for i, (doctor_id, doctor_info) in enumerate(self.doctor_ids.items(), 1):
            print(f"   {i}. {doctor_info['name']} ({doctor_info['jobTitle']}) - ID: {doctor_id}")
        
        print(f"\n🔍 Starting monitoring loop...")
        
        iteration = 0
        while True:
            try:
                iteration += 1
                timestamp = datetime.now(self.cst_tz).strftime('%Y-%m-%d %H:%M:%S CST')
                
                # Refresh doctor IDs every hour
                if iteration % 180 == 0:  # 180 iterations = 1 hour at 20s intervals
                    refresh_time = datetime.now(self.cst_tz).strftime('%Y-%m-%d %H:%M:%S CST')
                    print(f"\n[{refresh_time}] 🔄 Refreshing doctor IDs (hourly update - retrieving docs for next 7 days)...")
                    
                    # Store previous doctor info for comparison
                    previous_doctors = dict(self.doctor_ids)
                    previous_count = len(previous_doctors)
                    
                    # Refresh doctor IDs
                    self.doctor_ids = await self.collect_all_doctor_ids()
                    
                    if not self.doctor_ids:
                        print(f"[{refresh_time}] ❌ No doctors found during refresh! Continuing with previous list...")
                        self.doctor_ids = previous_doctors  # Restore previous list
                    else:
                        current_count = len(self.doctor_ids)
                        print(f"[{refresh_time}] ✅ Doctor IDs refreshed successfully: {previous_count} → {current_count} doctors")
                        
                        # Check for new doctors
                        new_doctors = [d for d_id, d in self.doctor_ids.items() if d_id not in previous_doctors]
                        removed_doctors = [d for d_id, d in previous_doctors.items() if d_id not in self.doctor_ids]
                        
                        if new_doctors:
                            print(f"[{refresh_time}] 🆕 New doctors found ({len(new_doctors)}):")
                            for doctor in new_doctors:
                                print(f"   + {doctor['name']} ({doctor['jobTitle']}) - ID: {doctor['id']}")
                        
                        if removed_doctors:
                            print(f"[{refresh_time}] ❌ Doctors no longer available ({len(removed_doctors)}):")
                            for doctor in removed_doctors:
                                print(f"   - {doctor['name']} ({doctor['jobTitle']}) - ID: {doctor['id']}")
                        
                        if not new_doctors and not removed_doctors:
                            print(f"[{refresh_time}] 📋 No changes in doctor availability")
                        
                        # Show current doctor list if there were changes
                        if new_doctors or removed_doctors:
                            print(f"[{refresh_time}] 🎯 Updated doctor list:")
                            for i, (doctor_id, doctor_info) in enumerate(self.doctor_ids.items(), 1):
                                print(f"   {i}. {doctor_info['name']} ({doctor_info['jobTitle']}) - ID: {doctor_id}")
                    
                    # Log the refresh with detailed information
                    with open(self.log_file, "a", encoding="utf-8") as f:
                        f.write(f"[{refresh_time}] Doctor IDs refreshed - {len(self.doctor_ids)} doctors found\n")
                        if new_doctors:
                            f.write(f"[{refresh_time}] New doctors: {', '.join([d['name'] for d in new_doctors])}\n")
                        if removed_doctors:
                            f.write(f"[{refresh_time}] Removed doctors: {', '.join([d['name'] for d in removed_doctors])}\n")
                    
                    with open(self.reg_log_file, "a", encoding="utf-8") as f:
                        f.write(f"[{refresh_time}] Doctor IDs refreshed - {len(self.doctor_ids)} doctors found\n")
                
                print(f"\n[{timestamp}] 🔍 Iteration {iteration} - Checking all doctors concurrently...")
                
                # Check all doctors concurrently
                async with aiohttp.ClientSession() as session:
                    # Create tasks for concurrent requests
                    tasks = []
                    for doctor_id, doctor_info in self.doctor_ids.items():
                        tasks.append(self.check_doctor_availability(session, doctor_id, doctor_info))
                    
                    # Execute all requests concurrently
                    results = await asyncio.gather(*tasks)
                
                # Process results
                all_available_slots = []
                total_slots_checked = 0
                
                for i, (doctor_id, doctor_info) in enumerate(self.doctor_ids.items()):
                    available_slots = results[i]
                    
                    if available_slots:
                        all_available_slots.extend(available_slots)
                        print(f"   ✅ Dr. {doctor_info['name']}: {len(available_slots)} slots available")
                    else:
                        print(f"   ❌ Dr. {doctor_info['name']}: No slots available")
                    
                    total_slots_checked += 1
                
                # Process results
                if all_available_slots:
                    await self.notify_user(all_available_slots)
                else:
                    print(f"[{timestamp}] No available slots found across all {len(self.doctor_ids)} doctors")
                    self.log_regular_check(len(self.doctor_ids), total_slots_checked)
                
                # Wait before next check
                print(f"[{timestamp}] Waiting {self.check_interval} seconds until next check...")
                await asyncio.sleep(self.check_interval)
                
            except KeyboardInterrupt:
                stop_time_cst = datetime.now(self.cst_tz).strftime('%Y-%m-%d %H:%M:%S CST')
                print(f"\n\n⏹️  Monitor stopped by user at {stop_time_cst}")
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(f"Monitor stopped at: {stop_time_cst}\n")
                with open(self.reg_log_file, "a", encoding="utf-8") as f:
                    f.write(f"Monitor stopped at: {stop_time_cst}\n")
                
                # Add session end marker to logs
                print("📝 Logging session end...")
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(f"[{stop_time_cst}] 🏁 Monitoring session ended\n")
                    f.write(f"{'='*60}\n\n")
                
                with open(self.reg_log_file, "a", encoding="utf-8") as f:
                    f.write(f"[{stop_time_cst}] 🏁 Monitoring session ended\n")
                    f.write(f"{'='*60}\n\n")
                
                print("✅ Session logged successfully!")
                break
                
            except Exception as e:
                error_time = datetime.now(self.cst_tz).strftime('%Y-%m-%d %H:%M:%S CST')
                print(f"[{error_time}] Error: {e}")
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(f"Error at {error_time}: {e}\n")
                with open(self.reg_log_file, "a", encoding="utf-8") as f:
                    f.write(f"Error at {error_time}: {e}\n")
                
                # Wait before retry
                error_wait = random.uniform(10, 20)
                print(f"[{error_time}] Waiting {error_wait:.1f} seconds before retry...")
                await asyncio.sleep(error_wait)

if __name__ == "__main__":
    monitor = StomatologyMonitor()
    asyncio.run(monitor.run_monitor()) 