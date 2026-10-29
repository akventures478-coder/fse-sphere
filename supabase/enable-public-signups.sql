-- FSE Sphere multi-user sign-up migration
-- Run ONCE in Supabase SQL Editor AFTER the original schema.sql has already run.
-- Removes the single-account restriction, adds admin approval, and replaces single-user RLS policies.

-- 1. Remove the original Auth trigger that rejected every email except the Master Admin.
drop trigger if exists enforce_fse_single_account_before_write on auth.users;
drop function if exists public.enforce_fse_single_account();

-- 2. Add approval status. Existing Master Admin is approved; new students default to unverified.
alter table public.profiles add column if not exists is_verified boolean not null default false;
update public.profiles set is_verified = true where lower(email) = '27-swyam.sanchit@fiib.edu.in';

create or replace function public.is_fse_workspace_admin()
returns boolean language sql stable security invoker set search_path = '' as $$
  select lower(coalesce(auth.jwt() ->> 'email', '')) = '27-swyam.sanchit@fiib.edu.in';
$$;
revoke all on function public.is_fse_workspace_admin() from public, anon;
grant execute on function public.is_fse_workspace_admin() to authenticated;

-- Security-definer helpers avoid RLS recursion in group and verification checks.
create or replace function public.is_fse_member_verified()
returns boolean language sql stable security definer set search_path = '' as $$
  select public.is_fse_workspace_admin() or exists (
    select 1 from public.profiles p where p.id = auth.uid() and p.is_verified = true
  );
$$;
revoke all on function public.is_fse_member_verified() from public, anon;
grant execute on function public.is_fse_member_verified() to authenticated;

create or replace function public.is_fse_group_member(p_group_id uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.group_members gm where gm.group_id = p_group_id and gm.user_id = auth.uid());
$$;
revoke all on function public.is_fse_group_member(uuid) from public, anon;
grant execute on function public.is_fse_group_member(uuid) to authenticated;

create or replace function public.can_join_fse_group(p_group_id uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select public.is_fse_workspace_admin() or exists (
    select 1 from public.groups g where g.id = p_group_id and (g.visibility = 'public' or g.owner_id = auth.uid())
  );
$$;
revoke all on function public.can_join_fse_group(uuid) from public, anon;
grant execute on function public.can_join_fse_group(uuid) to authenticated;

create or replace function public.is_fse_group_owner(p_group_id uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.groups g where g.id = p_group_id and g.owner_id = auth.uid());
$$;
revoke all on function public.is_fse_group_owner(uuid) from public, anon;
grant execute on function public.is_fse_group_owner(uuid) to authenticated;

-- Newly created Auth users get empty profiles and must be approved by the Master Admin.
create or replace function public.create_fse_profile_for_auth_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, email, display_name, username, is_verified)
  values (
    new.id,
    lower(new.email),
    coalesce(nullif(new.raw_user_meta_data ->> 'full_name',''), split_part(new.email,'@',1)),
    lower(regexp_replace(split_part(new.email,'@',1), '[^a-zA-Z0-9_.-]', '', 'g')) || '_' || left(new.id::text,6),
    lower(coalesce(new.email,'')) = '27-swyam.sanchit@fiib.edu.in'
  ) on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;
revoke all on function public.create_fse_profile_for_auth_user() from public, anon, authenticated;
drop trigger if exists on_auth_user_created_fse_profile on auth.users;
create trigger on_auth_user_created_fse_profile after insert on auth.users
for each row execute function public.create_fse_profile_for_auth_user();

-- Prevent a member from approving their own account through a direct API request.
create or replace function public.guard_fse_profile_verification()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.is_verified is distinct from old.is_verified and not public.is_fse_workspace_admin() then
    raise exception 'Only the FSE Sphere Master Admin can verify member accounts.';
  end if;
  return new;
end;
$$;
revoke all on function public.guard_fse_profile_verification() from public, anon, authenticated;
drop trigger if exists guard_fse_profile_verification_before_update on public.profiles;
create trigger guard_fse_profile_verification_before_update
before update of is_verified on public.profiles
for each row execute function public.guard_fse_profile_verification();

-- 3. Replace original single-account policies with member-safe policies.
-- Profiles: members can see/edit their own profile; Master Admin can review and verify all members.
drop policy if exists fse_profiles_select on public.profiles;
create policy fse_profiles_select on public.profiles for select to authenticated
using (id = (select auth.uid()) or (select public.is_fse_workspace_admin()));
drop policy if exists fse_profiles_insert on public.profiles;
create policy fse_profiles_insert on public.profiles for insert to authenticated
with check (id = (select auth.uid()) or (select public.is_fse_workspace_admin()));
drop policy if exists fse_profiles_update on public.profiles;
create policy fse_profiles_update on public.profiles for update to authenticated
using (id = (select auth.uid()) or (select public.is_fse_workspace_admin()))
with check (id = (select auth.uid()) or (select public.is_fse_workspace_admin()));
drop policy if exists fse_profiles_delete on public.profiles;
create policy fse_profiles_delete on public.profiles for delete to authenticated
using ((select public.is_fse_workspace_admin()));

-- Posts: any signed-in member can read; verified members can create/edit their own; Master Admin can moderate.
drop policy if exists fse_posts_select on public.posts;
create policy fse_posts_select on public.posts for select to authenticated using (true);
drop policy if exists fse_posts_insert on public.posts;
create policy fse_posts_insert on public.posts for insert to authenticated
with check (((select public.is_fse_member_verified()) and user_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));
drop policy if exists fse_posts_update on public.posts;
create policy fse_posts_update on public.posts for update to authenticated
using (((select public.is_fse_member_verified()) and user_id = (select auth.uid())) or (select public.is_fse_workspace_admin()))
with check (((select public.is_fse_member_verified()) and user_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));
drop policy if exists fse_posts_delete on public.posts;
create policy fse_posts_delete on public.posts for delete to authenticated
using (((select public.is_fse_member_verified()) and user_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));

-- Comments
drop policy if exists fse_comments_select on public.comments;
create policy fse_comments_select on public.comments for select to authenticated using (true);
drop policy if exists fse_comments_insert on public.comments;
create policy fse_comments_insert on public.comments for insert to authenticated
with check (((select public.is_fse_member_verified()) and user_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));
drop policy if exists fse_comments_update on public.comments;
create policy fse_comments_update on public.comments for update to authenticated
using (((select public.is_fse_member_verified()) and user_id = (select auth.uid())) or (select public.is_fse_workspace_admin()))
with check (((select public.is_fse_member_verified()) and user_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));
drop policy if exists fse_comments_delete on public.comments;
create policy fse_comments_delete on public.comments for delete to authenticated
using (((select public.is_fse_member_verified()) and user_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));

-- Reactions
drop policy if exists fse_reactions_select on public.reactions;
create policy fse_reactions_select on public.reactions for select to authenticated using (true);
drop policy if exists fse_reactions_insert on public.reactions;
create policy fse_reactions_insert on public.reactions for insert to authenticated
with check (((select public.is_fse_member_verified()) and user_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));
drop policy if exists fse_reactions_update on public.reactions;
create policy fse_reactions_update on public.reactions for update to authenticated
using (((select public.is_fse_member_verified()) and user_id = (select auth.uid())) or (select public.is_fse_workspace_admin()))
with check (((select public.is_fse_member_verified()) and user_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));
drop policy if exists fse_reactions_delete on public.reactions;
create policy fse_reactions_delete on public.reactions for delete to authenticated
using (((select public.is_fse_member_verified()) and user_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));

-- Follows
drop policy if exists fse_follows_select on public.follows;
create policy fse_follows_select on public.follows for select to authenticated using (true);
drop policy if exists fse_follows_insert on public.follows;
create policy fse_follows_insert on public.follows for insert to authenticated
with check (((select public.is_fse_member_verified()) and follower_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));
drop policy if exists fse_follows_delete on public.follows;
create policy fse_follows_delete on public.follows for delete to authenticated
using (((select public.is_fse_member_verified()) and follower_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));

-- Groups. Security-definer helper avoids circular RLS joins between groups and group_members.
drop policy if exists fse_groups_select on public.groups;
create policy fse_groups_select on public.groups for select to authenticated
using (visibility = 'public' or owner_id = (select auth.uid()) or (select public.is_fse_workspace_admin()) or (select public.is_fse_group_member(id)));
drop policy if exists fse_groups_insert on public.groups;
create policy fse_groups_insert on public.groups for insert to authenticated
with check (((select public.is_fse_member_verified()) and owner_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));
drop policy if exists fse_groups_update on public.groups;
create policy fse_groups_update on public.groups for update to authenticated
using (((select public.is_fse_member_verified()) and owner_id = (select auth.uid())) or (select public.is_fse_workspace_admin()))
with check (((select public.is_fse_member_verified()) and owner_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));
drop policy if exists fse_groups_delete on public.groups;
create policy fse_groups_delete on public.groups for delete to authenticated
using (((select public.is_fse_member_verified()) and owner_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));

-- Group membership
drop policy if exists fse_group_members_select on public.group_members;
create policy fse_group_members_select on public.group_members for select to authenticated
using (user_id = (select auth.uid()) or (select public.is_fse_workspace_admin()) or (select public.is_fse_group_member(group_id)));
drop policy if exists fse_group_members_insert on public.group_members;
create policy fse_group_members_insert on public.group_members for insert to authenticated
with check (((select public.is_fse_member_verified()) and user_id = (select auth.uid()) and (select public.can_join_fse_group(group_id))) or (select public.is_fse_workspace_admin()));
drop policy if exists fse_group_members_delete on public.group_members;
create policy fse_group_members_delete on public.group_members for delete to authenticated
using (((select public.is_fse_member_verified()) and (user_id = (select auth.uid()) or (select public.is_fse_group_owner(group_id)))) or (select public.is_fse_workspace_admin()));

-- Messages: members can access only their own direct conversations or groups they joined; Master Admin may moderate.
drop policy if exists fse_messages_select on public.messages;
create policy fse_messages_select on public.messages for select to authenticated
using ((select public.is_fse_workspace_admin()) or ((select public.is_fse_member_verified()) and
  (sender_id = (select auth.uid()) or recipient_id = (select auth.uid()) or
   (group_id is not null and exists (select 1 from public.group_members gm where gm.group_id = messages.group_id and gm.user_id = (select auth.uid()))))));
drop policy if exists fse_messages_insert on public.messages;
create policy fse_messages_insert on public.messages for insert to authenticated
with check ((select public.is_fse_workspace_admin()) or ((select public.is_fse_member_verified()) and sender_id = (select auth.uid()) and
  ((recipient_id is not null and group_id is null) or (recipient_id is null and group_id is not null and
   exists (select 1 from public.group_members gm where gm.group_id = messages.group_id and gm.user_id = (select auth.uid()))))));
drop policy if exists fse_messages_update on public.messages;
create policy fse_messages_update on public.messages for update to authenticated
using ((select public.is_fse_workspace_admin()) or ((select public.is_fse_member_verified()) and
  (sender_id = (select auth.uid()) or recipient_id = (select auth.uid()) or
   (group_id is not null and exists (select 1 from public.group_members gm where gm.group_id = messages.group_id and gm.user_id = (select auth.uid()))))))
with check ((select public.is_fse_workspace_admin()) or ((select public.is_fse_member_verified()) and
  (sender_id = (select auth.uid()) or recipient_id = (select auth.uid()) or
   (group_id is not null and exists (select 1 from public.group_members gm where gm.group_id = messages.group_id and gm.user_id = (select auth.uid()))))));
drop policy if exists fse_messages_delete on public.messages;
create policy fse_messages_delete on public.messages for delete to authenticated
using ((select public.is_fse_workspace_admin()) or ((select public.is_fse_member_verified()) and sender_id = (select auth.uid())));

-- Stories
drop policy if exists fse_stories_select on public.stories;
create policy fse_stories_select on public.stories for select to authenticated using (true);
drop policy if exists fse_stories_insert on public.stories;
create policy fse_stories_insert on public.stories for insert to authenticated
with check (((select public.is_fse_member_verified()) and author_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));
drop policy if exists fse_stories_update on public.stories;
create policy fse_stories_update on public.stories for update to authenticated
using (((select public.is_fse_member_verified()) and author_id = (select auth.uid())) or (select public.is_fse_workspace_admin()))
with check (((select public.is_fse_member_verified()) and author_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));
drop policy if exists fse_stories_delete on public.stories;
create policy fse_stories_delete on public.stories for delete to authenticated
using (((select public.is_fse_member_verified()) and author_id = (select auth.uid())) or (select public.is_fse_workspace_admin()));

-- No demo users or content are inserted by this migration.
