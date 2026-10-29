-- FSE Sphere / Supabase initial schema
-- Run in the Supabase SQL Editor after creating the project.
-- This setup restricts table access to the configured workspace email.
-- Public sign-ups should also be disabled in Supabase Auth settings.

create extension if not exists pgcrypto with schema extensions;

-- Enforce a single allowed Auth identity. This complements disabling public sign-ups in Auth settings.
create or replace function public.enforce_fse_single_account()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if lower(coalesce(new.email, '')) <> 'swyamsanchit987@gmail.com' then
    raise exception 'This FSE Sphere Supabase project is restricted to its configured administrator account.';
  end if;
  return new;
end;
$$;
revoke all on function public.enforce_fse_single_account() from public, anon, authenticated;
drop trigger if exists enforce_fse_single_account_before_write on auth.users;
create trigger enforce_fse_single_account_before_write
before insert or update of email on auth.users
for each row execute function public.enforce_fse_single_account();

create or replace function public.is_fse_workspace_admin()
returns boolean
language sql stable security invoker
set search_path = ''
as $$
  select lower(coalesce(auth.jwt() ->> 'email', '')) = 'swyamsanchit987@gmail.com';
$$;
revoke all on function public.is_fse_workspace_admin() from public, anon;
grant execute on function public.is_fse_workspace_admin() to authenticated;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null unique,
  display_name text not null default 'FSE Sphere Member',
  username text unique,
  bio text not null default '',
  avatar_url text,
  cover_url text,
  location text not null default '',
  website text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  body text not null default '',
  link_url text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint posts_body_or_link check (length(trim(body)) > 0 or link_url is not null)
);
create index if not exists posts_created_at_idx on public.posts (created_at desc);

create table if not exists public.comments (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  body text not null check (length(trim(body)) > 0),
  created_at timestamptz not null default now()
);
create index if not exists comments_post_id_created_at_idx on public.comments (post_id, created_at);

create table if not exists public.reactions (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  reaction_type text not null default 'like',
  created_at timestamptz not null default now(),
  unique (post_id, user_id, reaction_type)
);

create table if not exists public.follows (
  follower_id uuid not null references auth.users(id) on delete cascade,
  following_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (follower_id, following_id),
  constraint follows_not_self check (follower_id <> following_id)
);

create table if not exists public.groups (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(trim(name)) > 0),
  description text not null default '',
  visibility text not null default 'public' check (visibility in ('public','private')),
  owner_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.group_members (
  group_id uuid not null references public.groups(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  member_role text not null default 'member' check (member_role in ('owner','admin','member')),
  joined_at timestamptz not null default now(),
  primary key (group_id, user_id)
);
create index if not exists group_members_user_id_idx on public.group_members (user_id);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references auth.users(id) on delete cascade,
  recipient_id uuid references auth.users(id) on delete cascade,
  group_id uuid references public.groups(id) on delete cascade,
  body text not null default '',
  attachment_url text,
  created_at timestamptz not null default now(),
  read_at timestamptz,
  constraint messages_direct_or_group check ((recipient_id is not null and group_id is null) or (recipient_id is null and group_id is not null)),
  constraint messages_body_or_attachment check (length(trim(body)) > 0 or attachment_url is not null)
);
create index if not exists messages_direct_idx on public.messages (sender_id, recipient_id, created_at desc);
create index if not exists messages_group_idx on public.messages (group_id, created_at desc);

create table if not exists public.stories (
  id uuid primary key default gen_random_uuid(),
  author_id uuid not null references auth.users(id) on delete cascade,
  text text not null default '',
  media_url text,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '24 hours'),
  constraint stories_text_or_media check (length(trim(text)) > 0 or media_url is not null)
);
create index if not exists stories_expires_at_idx on public.stories (expires_at desc);

-- New Supabase Auth users get a blank profile; no fake profiles are inserted.
create or replace function public.create_fse_profile_for_auth_user()
returns trigger language plpgsql security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, display_name, username)
  values (
    new.id,
    lower(new.email),
    coalesce(nullif(new.raw_user_meta_data ->> 'full_name',''), split_part(new.email,'@',1)),
    lower(regexp_replace(split_part(new.email,'@',1), '[^a-zA-Z0-9_.-]', '', 'g'))
  ) on conflict (id) do update set email=excluded.email;
  return new;
end;
$$;
revoke all on function public.create_fse_profile_for_auth_user() from public, anon, authenticated;
drop trigger if exists on_auth_user_created_fse_profile on auth.users;
create trigger on_auth_user_created_fse_profile after insert on auth.users
for each row execute function public.create_fse_profile_for_auth_user();


-- Backfill the one administrator profile if the Auth user was created before this schema was applied.
insert into public.profiles (id, email, display_name, username)
select
  u.id,
  lower(u.email),
  coalesce(nullif(u.raw_user_meta_data ->> 'full_name',''), nullif(u.raw_user_meta_data ->> 'name',''), split_part(u.email,'@',1)),
  lower(regexp_replace(split_part(u.email,'@',1), '[^a-zA-Z0-9_.-]', '', 'g'))
from auth.users u
where lower(coalesce(u.email,'')) = 'swyamsanchit987@gmail.com'
on conflict (id) do update set email=excluded.email;

-- Enable RLS on every table exposed through the Data API.
alter table public.profiles enable row level security;
alter table public.posts enable row level security;
alter table public.comments enable row level security;
alter table public.reactions enable row level security;
alter table public.follows enable row level security;
alter table public.groups enable row level security;
alter table public.group_members enable row level security;
alter table public.messages enable row level security;
alter table public.stories enable row level security;

-- Remove default browser-role privileges; then grant only CRUD needed by the signed-in app.
revoke all on public.profiles, public.posts, public.comments, public.reactions, public.follows,
  public.groups, public.group_members, public.messages, public.stories from anon, authenticated;
grant select, insert, update, delete on public.profiles, public.posts, public.comments, public.reactions,
  public.follows, public.groups, public.group_members, public.messages, public.stories to authenticated;

-- Profiles: the one configured workspace account can read the workspace and update only its own row.
drop policy if exists fse_profiles_select on public.profiles;
create policy fse_profiles_select on public.profiles for select to authenticated using ((select public.is_fse_workspace_admin()));
drop policy if exists fse_profiles_insert on public.profiles;
create policy fse_profiles_insert on public.profiles for insert to authenticated with check ((select public.is_fse_workspace_admin()) and id=(select auth.uid()));
drop policy if exists fse_profiles_update on public.profiles;
create policy fse_profiles_update on public.profiles for update to authenticated using ((select public.is_fse_workspace_admin()) and id=(select auth.uid())) with check ((select public.is_fse_workspace_admin()) and id=(select auth.uid()));
drop policy if exists fse_profiles_delete on public.profiles;
create policy fse_profiles_delete on public.profiles for delete to authenticated using ((select public.is_fse_workspace_admin()) and id=(select auth.uid()));

-- Posts
 drop policy if exists fse_posts_select on public.posts;
create policy fse_posts_select on public.posts for select to authenticated using ((select public.is_fse_workspace_admin()));
drop policy if exists fse_posts_insert on public.posts;
create policy fse_posts_insert on public.posts for insert to authenticated with check ((select public.is_fse_workspace_admin()) and user_id=(select auth.uid()));
drop policy if exists fse_posts_update on public.posts;
create policy fse_posts_update on public.posts for update to authenticated using ((select public.is_fse_workspace_admin()) and user_id=(select auth.uid())) with check ((select public.is_fse_workspace_admin()) and user_id=(select auth.uid()));
drop policy if exists fse_posts_delete on public.posts;
create policy fse_posts_delete on public.posts for delete to authenticated using ((select public.is_fse_workspace_admin()) and user_id=(select auth.uid()));

-- Comments and reactions
 drop policy if exists fse_comments_select on public.comments;
create policy fse_comments_select on public.comments for select to authenticated using ((select public.is_fse_workspace_admin()));
drop policy if exists fse_comments_insert on public.comments;
create policy fse_comments_insert on public.comments for insert to authenticated with check ((select public.is_fse_workspace_admin()) and user_id=(select auth.uid()));
drop policy if exists fse_comments_update on public.comments;
create policy fse_comments_update on public.comments for update to authenticated using ((select public.is_fse_workspace_admin()) and user_id=(select auth.uid())) with check ((select public.is_fse_workspace_admin()) and user_id=(select auth.uid()));
drop policy if exists fse_comments_delete on public.comments;
create policy fse_comments_delete on public.comments for delete to authenticated using ((select public.is_fse_workspace_admin()) and user_id=(select auth.uid()));
drop policy if exists fse_reactions_select on public.reactions;
create policy fse_reactions_select on public.reactions for select to authenticated using ((select public.is_fse_workspace_admin()));
drop policy if exists fse_reactions_insert on public.reactions;
create policy fse_reactions_insert on public.reactions for insert to authenticated with check ((select public.is_fse_workspace_admin()) and user_id=(select auth.uid()));
drop policy if exists fse_reactions_update on public.reactions;
create policy fse_reactions_update on public.reactions for update to authenticated using ((select public.is_fse_workspace_admin()) and user_id=(select auth.uid())) with check ((select public.is_fse_workspace_admin()) and user_id=(select auth.uid()));
drop policy if exists fse_reactions_delete on public.reactions;
create policy fse_reactions_delete on public.reactions for delete to authenticated using ((select public.is_fse_workspace_admin()) and user_id=(select auth.uid()));

-- Follow relationships
 drop policy if exists fse_follows_select on public.follows;
create policy fse_follows_select on public.follows for select to authenticated using ((select public.is_fse_workspace_admin()));
drop policy if exists fse_follows_insert on public.follows;
create policy fse_follows_insert on public.follows for insert to authenticated with check ((select public.is_fse_workspace_admin()) and follower_id=(select auth.uid()));
drop policy if exists fse_follows_delete on public.follows;
create policy fse_follows_delete on public.follows for delete to authenticated using ((select public.is_fse_workspace_admin()) and follower_id=(select auth.uid()));

-- Groups: only an owner can edit/delete their group. No sample groups are inserted.
 drop policy if exists fse_groups_select on public.groups;
create policy fse_groups_select on public.groups for select to authenticated using ((select public.is_fse_workspace_admin()));
drop policy if exists fse_groups_insert on public.groups;
create policy fse_groups_insert on public.groups for insert to authenticated with check ((select public.is_fse_workspace_admin()) and owner_id=(select auth.uid()));
drop policy if exists fse_groups_update on public.groups;
create policy fse_groups_update on public.groups for update to authenticated using ((select public.is_fse_workspace_admin()) and owner_id=(select auth.uid())) with check ((select public.is_fse_workspace_admin()) and owner_id=(select auth.uid()));
drop policy if exists fse_groups_delete on public.groups;
create policy fse_groups_delete on public.groups for delete to authenticated using ((select public.is_fse_workspace_admin()) and owner_id=(select auth.uid()));

-- Group membership: users can read workspace memberships and manage their own membership row.
 drop policy if exists fse_group_members_select on public.group_members;
create policy fse_group_members_select on public.group_members for select to authenticated using ((select public.is_fse_workspace_admin()));
drop policy if exists fse_group_members_insert on public.group_members;
create policy fse_group_members_insert on public.group_members for insert to authenticated with check ((select public.is_fse_workspace_admin()) and user_id=(select auth.uid()));
drop policy if exists fse_group_members_delete on public.group_members;
create policy fse_group_members_delete on public.group_members for delete to authenticated using ((select public.is_fse_workspace_admin()) and user_id=(select auth.uid()));

-- Direct/group messages: only the allowed account is admitted; identity checks still apply.
 drop policy if exists fse_messages_select on public.messages;
create policy fse_messages_select on public.messages for select to authenticated using ((select public.is_fse_workspace_admin()) and (sender_id=(select auth.uid()) or recipient_id=(select auth.uid()) or group_id in (select gm.group_id from public.group_members gm where gm.user_id=(select auth.uid()))));
drop policy if exists fse_messages_insert on public.messages;
create policy fse_messages_insert on public.messages for insert to authenticated with check ((select public.is_fse_workspace_admin()) and sender_id=(select auth.uid()) and ((recipient_id is not null and group_id is null) or (recipient_id is null and group_id is not null and group_id in (select gm.group_id from public.group_members gm where gm.user_id=(select auth.uid())))));
drop policy if exists fse_messages_update on public.messages;
create policy fse_messages_update on public.messages for update to authenticated using ((select public.is_fse_workspace_admin()) and (sender_id=(select auth.uid()) or recipient_id=(select auth.uid()))) with check ((select public.is_fse_workspace_admin()) and (sender_id=(select auth.uid()) or recipient_id=(select auth.uid())));
drop policy if exists fse_messages_delete on public.messages;
create policy fse_messages_delete on public.messages for delete to authenticated using ((select public.is_fse_workspace_admin()) and sender_id=(select auth.uid()));

-- Stories
 drop policy if exists fse_stories_select on public.stories;
create policy fse_stories_select on public.stories for select to authenticated using ((select public.is_fse_workspace_admin()));
drop policy if exists fse_stories_insert on public.stories;
create policy fse_stories_insert on public.stories for insert to authenticated with check ((select public.is_fse_workspace_admin()) and author_id=(select auth.uid()));
drop policy if exists fse_stories_update on public.stories;
create policy fse_stories_update on public.stories for update to authenticated using ((select public.is_fse_workspace_admin()) and author_id=(select auth.uid())) with check ((select public.is_fse_workspace_admin()) and author_id=(select auth.uid()));
drop policy if exists fse_stories_delete on public.stories;
create policy fse_stories_delete on public.stories for delete to authenticated using ((select public.is_fse_workspace_admin()) and author_id=(select auth.uid()));

-- Intentionally no INSERT statements: this schema creates tables/policies only, no dummy rows.
