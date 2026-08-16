"""
Doctors to watch.

Each `payload` is the JSON body the 华医通 app sends for that doctor's
detail page (capture with a proxy). `timestamp` is filled at request time.
Capture 2026-08-15: empty dept/area/card; `encrypt` from that session.
"""

DOCTORS = [
    {
        "name": "赵宇 (耳鼻喉头颈外科)",
        "payload": {
            "hospitalCode": "HID0101",
            "deptCode": "",
            "doctorId": "4028b881646e3d8701646e3d873c00df",
            "channelCode": "PATIENT_IOS",
            "appCode": "HXGYAPP",
            "hospitalAreaCode": "",
            "tabAreaCode": "",
            "cardId": "",
            "encrypt": "Q6mg66/ILN5Yd69ATVVCcg==",
            "deptCategoryCode": "",
            "appointmentType": "1",
        },
    },
    # {
    #     "name": "伍俊良 (美容烧伤整形)",
    #     "payload": {
    #         "hospitalCode": "HID0101",
    #         "deptCode": "",
    #         "doctorId": "4028b881646e3d8701646e3d87190048",
    #         "channelCode": "PATIENT_IOS",
    #         "appCode": "HXGYAPP",
    #         "hospitalAreaCode": "",
    #         "tabAreaCode": "",
    #         "cardId": "",
    #         "encrypt": "u5kuL5Y8uJHjzPNAf+Ll+w==",
    #         "deptCategoryCode": "",
    #         "appointmentType": "1",
    #     },
    # },
]
