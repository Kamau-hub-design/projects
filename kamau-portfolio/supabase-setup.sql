-- Owner-only project management with public project listings.
-- 1. Create a Supabase project and enable email/password authentication.
-- 2. Create/confirm your owner account in Supabase Auth.
-- 3. Replace YOUR_OWNER_EMAIL in each policy below with that account's email.
-- 4. Run this script in the Supabase SQL Editor.
-- 5. Add the project URL, publishable/anon key, and the same owner email
--    to supabase-config.js. Never use a service-role key in the website.

create table if not exists public.projects (
    id uuid primary key default gen_random_uuid(),
    title text not null check (char_length(trim(title)) between 1 and 100),
    description text not null check (char_length(trim(description)) between 1 and 500),
    category text not null default 'Project' check (char_length(category) <= 60),
    technologies text[] not null default '{}',
    project_url text check (project_url is null or project_url ~ '^https?://'),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create unique index if not exists projects_title_unique_idx on public.projects (title);

insert into public.projects (title, description, category)
values (
    'Campus Companion',
    'Project details and technologies have not been published yet. Update this entry in the owner dashboard when ready.',
    'Project'
)
on conflict (title) do nothing;

alter table public.projects enable row level security;

grant select on public.projects to anon, authenticated;
grant insert, update, delete on public.projects to authenticated;

drop policy if exists "Public can read projects" on public.projects;
create policy "Public can read projects"
    on public.projects for select
    to anon, authenticated
    using (true);

drop policy if exists "Owner can insert projects" on public.projects;
create policy "Owner can insert projects"
    on public.projects for insert
    to authenticated
    with check (lower(coalesce(auth.jwt() ->> 'email', '')) = lower('YOUR_OWNER_EMAIL'));

drop policy if exists "Owner can update projects" on public.projects;
create policy "Owner can update projects"
    on public.projects for update
    to authenticated
    using (lower(coalesce(auth.jwt() ->> 'email', '')) = lower('YOUR_OWNER_EMAIL'))
    with check (lower(coalesce(auth.jwt() ->> 'email', '')) = lower('YOUR_OWNER_EMAIL'));

drop policy if exists "Owner can delete projects" on public.projects;
create policy "Owner can delete projects"
    on public.projects for delete
    to authenticated
    using (lower(coalesce(auth.jwt() ->> 'email', '')) = lower('YOUR_OWNER_EMAIL'));
