"""
Doctor configuration for the West China Hospital appointment monitor.

Add or modify doctors to monitor by editing the DOCTORS list.
"""

DOCTORS = [
    {
        "name": "伍俊良 (整形外科/烧伤科)",
        "payload": {
            "hospitalCode": "HID0101",
            "deptCode": "",
            "doctorId": "4028b881646e3d8701646e3d87190048",
            "channelCode": "PATIENT_IOS",
            "appCode": "HXGYAPP",
            "hospitalAreaCode": "",
            "tabAreaCode": "",
            "cardId": "",
            "encrypt": "aI7cGAvltRxXZCwGbqfLaw==",
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
