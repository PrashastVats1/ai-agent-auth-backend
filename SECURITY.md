# Security policy

This project handles authentication, so security reports matter.

## Reporting a vulnerability

**Please don't open a public issue.** Use GitHub's private reporting instead: open this repository's **Security** tab and choose **Report a vulnerability**.

Include what you found, how to reproduce it, and what an attacker could do with it. This is a small open-source project, so replies are best-effort, but reports are taken seriously and you'll be credited in the fix if you'd like.

## Supported versions

Only the latest commit on `main` is supported.

## Scope

In scope: token validation (MonoCloud JWTs and delegation JWTs), agent ownership and consent checks, policy enforcement, and anything that leaks one user's data to another.

Out of scope: vulnerabilities in MonoCloud, Neon, Render or Vercel themselves; report those to the vendor.
