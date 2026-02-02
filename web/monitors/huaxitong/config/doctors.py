"""
Doctor configuration for the West China Hospital appointment monitor.

Add or modify doctors to monitor by editing the DOCTORS list.
"""

DOCTORS = [
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
    },
    # Add more doctors here as needed:
    # {
    #     "name": "Doctor Name (Department)",
    #     "payload": {
    #         "hospitalCode": "HID0101",
    #         "deptCode": "",
    #         "doctorId": "doctor_id_here",
    #         "channelCode": "PATIENT_IOS",
    #         "appCode": "HXGYAPP",
    #         "hospitalAreaCode": "",
    #         "tabAreaCode": "",
    #         "cardId": "",
    #         "encrypt": "encrypt_value_here",
    #         "deptCategoryCode": "",
    #         "appointmentType": "1"
    #     }
    # },
]
