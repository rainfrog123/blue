# HXGY IDOR - Leaked PII Records

Collected via IDOR vulnerability in `/cloud/guidance/admission/queryAdmission` endpoint.

## userId: 285000

| Field | Value |
|-------|-------|
| Patient Name | 李彧 |
| Sex | Female (2) |
| PMI | 17983862 |
| PMI No | 0018003454 |
| Card ID | 300274575793590272 |
| Department | 便民门诊 |
| Doctor | 陈励耘 |
| Hospital | 四川大学华西医院 (华西院区) |
| Appointment | 2025-04-09 |

```json
{
  "seq": "1909761014794215425",
  "type": "zzkd",
  "organCode": "HID0101",
  "organName": "四川大学华西医院",
  "deptName": "便民门诊",
  "cardId": "300274575793590272",
  "admId": "193084549",
  "userId": "285000",
  "sex": 2,
  "patientName": "李彧",
  "admNo": null,
  "medicalDiagnosisNumber": null,
  "pmi": "17983862",
  "pmiNo": "0018003454",
  "hospitalName": "四川大学华西医院",
  "hospitalArea": "华西院区",
  "hospitalAddress": "成都市武侯区国学巷37号",
  "toDoEventNum": 0,
  "doctorId": "36440",
  "doctorName": "陈励耘",
  "admTime": "2025-04-09 星期三 上午 ",
  "admTimeToComputation": "2025-04-09T00:00:00",
  "createTime": "2025-04-09T08:11:22"
}
```

---

## userId: 285002

| Field | Value |
|-------|-------|
| Patient Name | 徐琳珂 |
| Sex | Female (2) |
| PMI | 17575506 |
| PMI No | 0017595099 |
| Card ID | 278942272798724096 |
| Department | 眼科 (Ophthalmology) |
| Doctors | 向浩天, 廖祺 |
| Hospital | 四川大学华西医院 (华西院区) |
| Appointments | 2024-10-04, 2024-10-07 |

```json
[
  {
    "seq": "1840543598617903105",
    "type": "OFFLINE",
    "organCode": "HID0101",
    "organName": "四川大学华西医院",
    "deptName": "眼科",
    "cardId": "278942272798724096",
    "admId": "187237091",
    "userId": "285002",
    "sex": 2,
    "patientName": "徐琳珂",
    "admNo": null,
    "medicalDiagnosisNumber": "3",
    "pmi": "17575506",
    "pmiNo": "0017595099",
    "hospitalName": "四川大学华西医院",
    "hospitalArea": "华西院区",
    "hospitalAddress": "成都市武侯区国学巷37号",
    "toDoEventNum": 2,
    "doctorId": "2c93808270f1f7980171402d53016737",
    "doctorName": "向浩天",
    "admTime": "2024-10-07 星期一 下午 12:30-13:00",
    "admTimeToComputation": "2024-10-07T00:00:00",
    "createTime": "2024-09-30T08:06:04"
  },
  {
    "seq": "1840000172328595457",
    "type": "OFFLINE",
    "organCode": "HID0101",
    "organName": "四川大学华西医院",
    "deptName": "眼科",
    "cardId": "278942272798724096",
    "admId": "187218225",
    "userId": "285002",
    "sex": 2,
    "patientName": "徐琳珂",
    "admNo": null,
    "medicalDiagnosisNumber": "15",
    "pmi": "17575506",
    "pmiNo": "0017595099",
    "hospitalName": "四川大学华西医院",
    "hospitalArea": "华西院区",
    "hospitalAddress": "成都市武侯区国学巷37号",
    "toDoEventNum": 0,
    "doctorId": "1740648107444170752",
    "doctorName": "廖祺",
    "admTime": "2024-10-04 星期五 下午 14:00-14:30",
    "admTimeToComputation": "2024-10-04T00:00:00",
    "createTime": "2024-09-28T20:06:41"
  }
]
```

---

## userId: 295000

| Field | Value |
|-------|-------|
| Patient Name | 王莎 |
| Sex | Female (2) |
| PMI | 54390316 |
| PMI No | 0036390260 |
| Card ID | 477112798539812864 |
| Department | 胆道外科病房 (Biliary Surgery Ward) |
| Doctors | 游蓁, 陈利平 |
| Hospital | 四川大学华西医院 (华西坝院区) |
| Visit Type | HOSPITALIZATION + OFFLINE |
| Dates | 2025-10-18, 2025-10-19, 2025-10-20 |

```json
[
  {
    "seq": "1980137753483755521",
    "type": "HOSPITALIZATION",
    "organCode": "HID0101",
    "organName": "四川大学华西医院",
    "deptName": "胆道外科病房",
    "cardId": "477112798539812864",
    "admId": "8452625",
    "userId": "295000",
    "sex": 2,
    "patientName": "王莎",
    "admNo": null,
    "medicalDiagnosisNumber": null,
    "pmi": "54390316",
    "pmiNo": "0036390260",
    "hospitalName": "四川大学华西医院",
    "hospitalArea": null,
    "hospitalAddress": null,
    "toDoEventNum": 1,
    "doctorId": "10774",
    "doctorName": "游蓁",
    "admTime": null,
    "admTimeToComputation": "2025-10-20T00:00:00",
    "createTime": "2025-10-20T13:03:24"
  },
  {
    "seq": "1979739304963686401",
    "type": "OFFLINE",
    "organCode": "HID0101",
    "organName": "四川大学华西医院",
    "deptName": "胆道外科病房",
    "cardId": "477112798539812864",
    "admId": "200036842",
    "userId": "295000",
    "sex": 2,
    "patientName": "王莎",
    "admNo": null,
    "medicalDiagnosisNumber": "36",
    "pmi": "54390316",
    "pmiNo": "0036390260",
    "hospitalName": "四川大学华西医院",
    "hospitalArea": "华西坝院区",
    "hospitalAddress": "成都市武侯区国学巷37号",
    "toDoEventNum": 0,
    "doctorId": "2c9580826bc3cfbc016bcf6e7ae704fb",
    "doctorName": "游蓁",
    "admTime": "2025-10-20 星期一 上午 10:45-11:15",
    "admTimeToComputation": "2025-10-20T00:00:00",
    "createTime": "2025-10-19T10:40:07"
  },
  {
    "seq": "1979345001309356033",
    "type": "OFFLINE",
    "organCode": "HID0101",
    "organName": "四川大学华西医院",
    "deptName": "胆道外科病房",
    "cardId": "477112798539812864",
    "admId": "200015348",
    "userId": "295000",
    "sex": 2,
    "patientName": "王莎",
    "admNo": null,
    "medicalDiagnosisNumber": "27",
    "pmi": "54390316",
    "pmiNo": "0036390260",
    "hospitalName": "四川大学华西医院",
    "hospitalArea": "华西坝院区",
    "hospitalAddress": "成都市武侯区国学巷37号",
    "toDoEventNum": 0,
    "doctorId": "4028b881646e3d8701646e3d873f00ff",
    "doctorName": "陈利平",
    "admTime": "2025-10-18 星期六 下午 14:00-14:30",
    "admTimeToComputation": "2025-10-18T00:00:00",
    "createTime": "2025-10-18T08:33:17"
  }
]
```

---

## userId: 279078

| Field | Value |
|-------|-------|
| Patient Name | 钟南山 |
| Sex | Male (1) |
| PMI | 16957642 |
| PMI No | 0016977239 |
| Card ID | 767948697713360896 |
| Department | 眼科 (Ophthalmology) |
| Doctor | 马可 |
| Hospital | 四川大学华西医院 (华西坝院区) |
| Appointment | 2025-05-05 |

```json
{
  "seq": "1916643732526129153",
  "type": "OFFLINE",
  "organCode": "HID0101",
  "organName": "四川大学华西医院",
  "deptName": "眼科",
  "cardId": "767948697713360896",
  "admId": "193768546",
  "userId": "279078",
  "sex": 1,
  "patientName": "钟南山",
  "admNo": null,
  "medicalDiagnosisNumber": "1",
  "pmi": "16957642",
  "pmiNo": "0016977239",
  "hospitalName": "四川大学华西医院",
  "hospitalArea": "华西坝院区",
  "hospitalAddress": "成都市武侯区国学巷37号",
  "toDoEventNum": 0,
  "doctorId": "4028b881646e3d8701646e3d876101cc",
  "doctorName": "马可",
  "admTime": "2025-05-05 星期一 下午 12:30-13:00",
  "admTimeToComputation": "2025-05-05T00:00:00",
  "createTime": "2025-04-28T08:00:50"
}
```

---

## Summary

| userId | Patient | Sex | Department | Records | Type |
|--------|---------|-----|------------|---------|------|
| 279078 | 钟南山 | M | 眼科 | 1 | OFFLINE |
| 285000 | 李彧 | F | 便民门诊 | 1 | zzkd |
| 285002 | 徐琳珂 | F | 眼科 | 2 | OFFLINE |
| 295000 | 王莎 | F | 胆道外科病房 | 3 | HOSPITALIZATION |

## Exposed Data Categories

| Category | Fields | Sensitivity |
|----------|--------|-------------|
| Identity | patientName, sex | **Critical** |
| Medical IDs | pmi, pmiNo, cardId | **Critical** |
| Medical Info | deptName, medicalDiagnosisNumber | **High** |
| Scheduling | admTime, createTime | **High** |
| Provider | doctorName, doctorId | Medium |
| Location | hospitalName, hospitalArea, hospitalAddress | Low |
