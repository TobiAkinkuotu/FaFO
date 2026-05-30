# Backend missing items (focus area)

This document captures the backend work that is still missing or incomplete in the current FAFO prototype.

## 1. Database/schema consistency
- The incidents table currently stores `created_by` as an integer user id, but several UI paths still treat it as a username string.
- The upload page previously queried `title`, but the schema does not contain a `title` column.
- The incident insert path was writing `status = 'Open'`, but the schema only allows `pending`, `under_review`, `approved`, `closed`, `escalated`.
- The evidence table is partially wired, but the metadata flow should be standardized and validated end to end.

## 2. Evidence processing pipeline
- OCR extraction is implemented, but it is not yet fully integrated into a reliable post-upload ingestion workflow.
- AI classification exists as a heuristic shell, but the production pipeline is not yet fully connected to incident review and escalation.
- Video/FFmpeg processing is present as a module, but not yet fully integrated into the case workflow.

## 3. Case lifecycle / review workflow
- Incident submission works at a basic level, but the full case lifecycle (review, approval, escalation, closure) is not yet fully automated.
- Lawyer/admin review pages are still mostly shells and mockups rather than real case-management workflows.
- Audit trail logging should be mandatory across all mutations: user creation, incident submission, evidence upload, AI approval, export generation.

## 4. Security and access control
- Authentication exists, but role enforcement should be stricter in every backend action.
- Session timeout and lockout logic are present, but all protected endpoints/actions should validate authorization consistently.
- JWT/session handling should be standardized and tested end to end.

## 5. Export and reporting
- PDF and ZIP export generation is present, but the full legal-review export flow is not yet fully connected to the main backend process.
- Export integrity, chain-of-custody manifests, and file hash verification should be validated as part of the backend pipeline.

## 6. Reliability / testing
- There is no real automated backend test suite yet.
- No regression tests exist for incident insert/query paths, evidence upload logic, and auth/session handling.
- Backend validation should include schema checks, query checks, and failure-path tests.

## 7. Immediate backend priorities
1. Standardize all incident and evidence SQL paths to the real schema.
2. Enforce correct `created_by` and `status` values on every incident submission.
3. Ensure all backend flows write consistent audit logs.
4. Add tests for the core backend paths before expanding new features.
