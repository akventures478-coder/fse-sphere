FSE SPHERE — SUPABASE MULTI-USER SIGN-UP PACKAGE
===================================

PROJECT CONNECTION
------------------
The Supabase Project URL and browser publishable key are configured in supabase-config.js for the fresh project.
The Supabase secret key is intentionally NOT included. Never place a secret/service_role key in browser code.

SECURITY ACTION REQUIRED
------------------------
A Supabase secret key was exposed in chat. Rotate/revoke it immediately in Supabase Dashboard > Project Settings > API Keys. Do not add the replacement secret to this package.
The website does not need a secret key. Do not share the replacement secret key or put it in this ZIP.

MAIN FILES
----------
index.html                         Sign-in/sign-up page and embedded dashboard
FSE_Club_Dashboard.html            Standalone dashboard source
supabase-config.js                 Configured Project URL + publishable key
supabase/schema.sql                Initial database tables and policies (already run)
supabase/enable-public-signups.sql Removes the one-account guard, adds member verification and member-aware RLS
netlify.toml / vercel.json         Static-host settings

WHAT WAS CLEANED
----------------
- Removed demo-login controls and local registration/OTP prototype flow.
- Removed preloaded demo users, feed posts, group records, inbox messages, notifications, stories, seeded market quotes and suggested profiles.
- Replaced sample profile identity, bio, location, and activity counters with neutral empty-state values.
- Upgraded the one-time browser cleanup to remove earlier FSE prototype data, including namespaced localStorage keys.
- Removed local-only account moderation actions that could falsely imply server-side account changes.
- Added a Supabase Auth email/password sign-in and sign-up flow.
- Configured 27-swyam.sanchit@fiib.edu.in as the fixed Master Admin identity; other sign-ups are regular members.
- Added a one-time migration to remove the single-email Auth guard, add member verification status and replace single-account RLS policies.
- Added Master Admin verification controls; unverified members stay in read-only preview mode.

NEXT STEPS
----------
1. In Supabase Authentication settings, enable Email provider and Allow new users to sign up.
2. For a completely new empty Supabase project, run supabase/schema.sql first, then run supabase/enable-public-signups.sql once. Do not run these against an existing database without reviewing its data and policies.
3. Confirm 27-swyam.sanchit@fiib.edu.in exists under Authentication > Users and is confirmed. This email is recognized as the Master Admin; new accounts are regular members. For an existing deployment, run supabase/set-master-admin-email.sql in the SAME Supabase project referenced by the deployed supabase-config.js.
4. Set the Supabase Site URL and allowed Redirect URLs to your deployed HTTPS domain in Authentication > URL Configuration.
5. Deploy the complete package. The Create account tab creates accounts using Supabase Auth; when email confirmation is required, the member must confirm their email first.
6. New members start in read-only preview mode. Sign in as the Master Admin and use 🛡️ Master tools > Verify to approve them; members should then sign out and sign in again.
7. Test one new email, an incorrect password, account email confirmation, and member verification before inviting students.

IMPORTANT LIMITATION
-------------------
This package wires Supabase email/password sign-in, account creation, profile verification status and the Master Admin verification screen to Supabase. The current feed, posts, groups and messages in the dashboard are still primarily browser-storage features and are NOT yet synchronized to Supabase tables across devices. Do not treat it as a fully production-backed social platform until those operations are migrated.

ADMIN FIX PACKAGE NOTE
----------------------
The Master Admin email has been changed throughout the sign-in page, embedded dashboard, standalone dashboard and SQL setup scripts to 27-swyam.sanchit@fiib.edu.in. Deploy the updated files to GitHub Pages; an updated ZIP alone does not change the live website.
