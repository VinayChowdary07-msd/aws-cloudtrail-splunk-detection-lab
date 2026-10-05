# Detections

Four SPL detections written against CloudTrail data in `index=aws_cloudtrail` (sourcetype `aws:cloudtrail`). Each was run over **all time** against the lab data and returned exactly the intended events.

| # | Detection | Validated result | MITRE ATT&CK |
|---|---|---|---|
| 1 | Admin policy attached to IAM user | 1 match (`lab-test-user`) | T1098.003 |
| 2 | S3 bucket ACL granted to public | 1 match (the public grant) | T1530 |
| 3 | S3 Block Public Access weakened | 1 match (the unblock event) | T1562 |
| 4 | S3 public exposure (correlated) | 1 row (one bucket, both signals) | T1530, T1562 |

> MITRE mappings are judgment calls. ATT&CK has no technique for "make a bucket public" itself, so T1530 is the access that this exposure enables. Verify mappings on attack.mitre.org before relying on them.

---

## 1. Admin policy attached to IAM user (T1098.003)

```spl
index=aws_cloudtrail eventSource=iam.amazonaws.com eventName=AttachUserPolicy requestParameters.policyArn="arn:aws:iam::aws:policy/AdministratorAccess"
| table _time userIdentity.type userIdentity.arn sourceIPAddress requestParameters.userName requestParameters.policyArn
```

- **Why the policy ARN:** a later, legitimate `AttachUserPolicy` (a custom read-only policy for the Splunk reader) produced the same event name, so the ARN is what separates it from an escalation.
- **Field correction:** the field is `requestParameters.policyArn`, not `policyName`.
- **False positives:** break-glass administrators, onboarding, infrastructure automation. Allow-list known admin identities by `userIdentity.arn`.
- **Gaps:** does not cover `AttachRolePolicy`, `AttachGroupPolicy`, inline policies (`PutUserPolicy`), `CreatePolicyVersion`, or other admin-equivalent policies.

## 2. S3 bucket ACL granted to public (T1530)

```spl
index=aws_cloudtrail eventName=PutBucketAcl ("groups/global/AllUsers" OR "groups/global/AuthenticatedUsers")
| table _time userIdentity.type sourceIPAddress requestParameters.bucketName
```

- **Why a text match:** CloudTrail records the grant as a nested `Grant` array containing the grantee URI. A raw-text match on the group URI was reliable with the add-on's field extraction.
- **Cleanup events:** the two ACL saves that removed the grant have an empty `AccessControlList`, so they do not match.
- **False positives:** intentionally public static-website or log-delivery buckets. Allow-list by bucket name.
- **Gaps:** does not cover `PutObjectAcl`, bucket policies with a wildcard principal (`PutBucketPolicy`), or access points.

## 3. S3 Block Public Access weakened (T1562)

```spl
index=aws_cloudtrail eventSource=s3.amazonaws.com eventName=PutBucketPublicAccessBlock
    (requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls=false
  OR requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls=false
  OR requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy=false
  OR requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets=false)
| table _time userIdentity.type sourceIPAddress requestParameters.bucketName
```

- **Why it matters:** it fires before any exposure exists, so it is the earliest warning of the three S3 signals.
- **Restore events:** the events that set all four values back to `true` do not match.
- **False positives:** buckets that are meant to be public. Allow-list by bucket name.
- **Gaps:** does not cover `DeletePublicAccessBlock`, which also removes the protection, or account-level settings changes (`PutAccountPublicAccessBlock`).

## 4. S3 public exposure, correlated (T1530, T1562)

```spl
index=aws_cloudtrail eventSource=s3.amazonaws.com
  ((eventName=PutBucketPublicAccessBlock
     (requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls=false
   OR requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls=false
   OR requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy=false
   OR requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets=false))
  OR (eventName=PutBucketAcl ("groups/global/AllUsers" OR "groups/global/AuthenticatedUsers")))
| eval bucket='requestParameters.bucketName'
| eval signal=if(eventName="PutBucketAcl","public_acl_granted","block_public_access_removed")
| stats min(_time) AS first_seen max(_time) AS last_seen dc(signal) AS signal_count values(signal) AS signals by bucket
| where signal_count=2 AND (last_seen-first_seen)<=900
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
```

- **Logic:** both signals on the same bucket within 900 seconds. Requiring two signals reduces false positives compared with either rule alone.
- **Lab result:** one row for the test bucket, first signal to last signal 4 minutes 17 seconds apart.
- **Gap:** the order of the two events is not enforced, which is a deliberate simplification.

---

## Alert configuration

| Setting | Value |
|---|---|
| Type | Scheduled, hourly (0 minutes past the hour) |
| Lookback | `-1h` to `now` |
| Trigger | Number of results > 0 |
| Action | Add to Triggered Alerts |
| Recommended | Throttle for 24 hours so one incident does not re-trigger every hour; severity High for the S3 exposure and admin-policy alerts |

**Note on validation:** because the lookback is one hour, the saved alerts did not fire on the previous day's lab events. Detection logic was validated by running each search over all time. A production deployment would also need real-time or SQS-driven ingestion to cut the polling delay.
