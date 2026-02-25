# Implementation Plan: Ephemeral delegation + hard block workshop credential sets

## Goal
Implement named-agent delegated ephemeral credential exchange and enforce server-side hard deny for workshop credential sets on ephemeral profiles.

## Key outcomes
- Add delegate token minting endpoint for named agents.
- Add credentials exchange endpoint for ephemeral sessions.
- Add profileType (`named|ephemeral`) and enforce workshop-set omission for ephemeral profiles.
- Extend admin CLI onboarding/seeding to set profile type.
