#!/usr/bin/env python3
"""
West China Hospital Appointment Monitor

Monitors doctor appointment availability and sends WeChat notifications
when slots become available.

Usage:
    python main.py              # Run monitor
    python main.py --test       # Test ServerChan notification
"""
import sys
import os

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.monitor import AppointmentMonitor
from src.notifiers import ServerChanNotifier


def main():
    """Main entry point."""
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        # Test notification mode
        print("Testing ServerChan notification...")
        notifier = ServerChanNotifier()
        success = notifier.test_connection()
        sys.exit(0 if success else 1)

    # Run monitor
    monitor = AppointmentMonitor()
    monitor.run()


if __name__ == "__main__":
    main()
