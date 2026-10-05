# Incident Investigation: Public S3 Bucket Exposure

| | |
|---|---|
| **Environment** | AWS (single account, us-east-1); CloudTrail → S3 → Splunk Enterprise |
| **Date of activity** | 2026-10-03 (all times UTC) |
| **Classification** | True positive, authorized simulation |
| **Severity (this incident)** | Low |
| **Severity (alert rule)** | High |

---

## 1. Alert

The correlation search **AWS - S3 public exposure (correlated)** matched bucket `soc-lab-public-test-<suffix>`. It fires when two signals appear on the same bucket within 15 minutes:

1. `PutBucketPublicAccessBlock` with any of the four protections set to `false`
2. `PutBucketAcl` granting access to the `AllUsers` or `AuthenticatedUsers` group

The search returned one row: first signal at 18:56:21Z, second at 19:00:38Z, **4 minutes 17 seconds** apart.

*Validation note:* the saved alert uses a 1-hour lookback, so it did not re-fire on the previous day's events. I validated the detection by running the same search over all time against the stored CloudTrail data.

## 2. Context

- The account is a personal lab account with no production workloads.
- The actor was the **root user**, in a console session that began at 18:16:26Z without MFA. A passkey was registered inside that same session at 18:31:18Z (`EnableMFADevice`), so every later event in the session, including this simulation, still records `mfaAuthenticated: false`. A fresh sign-in on 2026-10-04 at 07:05:27Z used MFA (`MFAUsed: Yes`).
- All events came from one source IP (`<REDACTED_IP>`), with a Chrome on Windows user agent and the S3 console as referrer. That pattern is consistent with a person using the console, not a script.
- The bucket was created at 18:54:29Z and contained no objects.

## 3. Evidence

| Time (UTC) | Event | Detail |
|---|---|---|
| 18:54:29 | `CreateBucket` | Test bucket created |
| 18:56:21 | `PutBucketPublicAccessBlock` | `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets` all `false` |
| 19:00:38 | `PutBucketAcl` | Grants: owner `FULL_CONTROL`; `AllUsers` (`http://acs.amazonaws.com/groups/global/AllUsers`) `READ` |
| 19:02:09 | `PutBucketPublicAccessBlock` | All four `true` |
| 19:03:55 | `PutBucketAcl` | Empty ACL, public grant removed |
| 19:04:25 | `PutBucketPublicAccessBlock` | All four `true` (repeat) |
| 19:04:43 | `PutBucketAcl` | Empty ACL (repeat) |
| 19:28:43 | `DeleteBucket` | Bucket deleted |

All events returned HTTP 200. Fields used: `eventName`, `eventTime`, `userIdentity.type`, `sourceIPAddress`, `userAgent`, `requestParameters.bucketName`, `requestParameters.AccessControlPolicy`, `requestParameters.PublicAccessBlockConfiguration`.

*Evidence artifacts (redacted):* CloudTrail JSON for the 18:56:21Z and 19:00:38Z events; Splunk result tables for each detection over all time; saved alert settings.

## 4. Analysis

### Exposure windows

| Window | Duration |
|---|---|
| Block Public Access off (18:56:21 to 19:02:09) | 5 min 48 s |
| Public ACL grant present (19:00:38 to 19:03:55) | 3 min 17 s |
| **Effective exposure** (19:00:38 to 19:02:09) | **about 1 min 31 s** |

The effective window is the overlap of the two. It assumes S3 behaves as documented, with `IgnorePublicAcls` neutralising public ACLs once it is turned back on.

### Reading the sequence

Protection was removed first, the public grant followed, and cleanup ran in the reverse order. That pattern could belong to a deliberate test, a careless administrator, or an attacker. What identifies this as a test is the actor (my own root session), the empty bucket, and the cleanup in the same session. In a production alert, none of those could be assumed without confirmation from the account owner.

### What the activity would mean in a real incident

`READ` for `AllUsers` on a bucket lets anyone on the internet list its contents. If the bucket held objects, this would enable **T1530 (Data from Cloud Storage)**. Removing Block Public Access maps to **T1562 (Impair Defenses)**. Both mappings are judgment calls.

### Limitations

- Only management events were logged, so I cannot show whether anyone listed or read the bucket during the 91-second window.
- No S3 server access logs were enabled.
- The bucket was empty, so no data was at risk.

## 5. Severity

| Scope | Rating | Reason |
|---|---|---|
| This incident | **Low** | Empty bucket, about 91 seconds of effective exposure, authorized actor, cleaned up in the same session |
| The alert rule in general | **High** | The same sequence on a bucket holding real data would warrant immediate response |

## 6. Decision

**True positive, authorized test. No escalation required.** In a production SOC I would confirm with the account owner before closing; here the owner is the analyst.

**Response actions taken:** Block Public Access restored, public grant removed, bucket deleted.

**Recommendations**

1. Enable **account-level** S3 Block Public Access so a single bucket change cannot expose data.
2. Add detections for `DeletePublicAccessBlock` and `PutBucketPolicy` with a wildcard principal, which are other exposure routes.
3. Enable S3 **data events** for sensitive buckets so access during an exposure can be reconstructed. They cost extra, so scope them.
4. Avoid routine work as the root user, and sign out and back in after registering MFA so the session itself carries MFA.

## 7. Documentation

- **Detection logic:** correlation SPL joining two signals per bucket within 900 seconds, mapped to T1530 and T1562. See [detections.md](detections.md).
- **Related detections:** admin policy attached to an IAM user (T1098.003); public ACL grant; Block Public Access weakened.
- **Redaction:** account ID, canonical user ID, source IP, access key IDs, session keys, and the passkey serial number are replaced with placeholders.
