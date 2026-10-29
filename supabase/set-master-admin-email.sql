-- FSE Sphere: switch the single Master Admin identity to the FIIB email.
-- Run this in the SAME Supabase project used by the deployed website.
-- Safe to run more than once. Do not disable RLS or the verification guard.

create or replace function public.is_fse_workspace_admin()
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select lower(coalesce(auth.jwt() ->> 'email', '')) = '27-swyam.sanchit@fiib.edu.in';
$$;

revoke all on function public.is_fse_workspace_admin() from public, anon;
grant execute on function public.is_fse_workspace_admin() to authenticated;

-- Your account was already verified; this statement only repairs it if it is ever false.
-- It may be blocked by the verification guard when run without a user JWT, so the
-- account should be verified through the existing authorized flow if it is not true.
update public.profiles
set is_verified = true
where lower(email) = '27-swyam.sanchit@fiib.edu.in'
  and is_verified is distinct from true;
