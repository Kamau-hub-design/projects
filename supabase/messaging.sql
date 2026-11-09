create table public.profiles (
    id uuid primary key references auth.users (id) on delete cascade,
    full_name text not null,
    role text not null default 'student'
        check (role in ('student', 'lecturer')),
    created_at timestamptz not null default now()
);

create table public.lecturer_applications (
    user_id uuid primary key references public.profiles (id) on delete cascade,
    status text not null default 'pending'
        check (status in ('pending', 'approved', 'rejected')),
    created_at timestamptz not null default now()
);

create or replace function public.create_student_profile()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    insert into public.profiles (id, full_name, role)
    values (
        new.id,
        coalesce(nullif(trim(new.raw_user_meta_data ->> 'full_name'), ''), 'Student'),
        'student'
    );

    if new.raw_user_meta_data ->> 'registration_type' = 'lecturer' then
        insert into public.lecturer_applications (user_id)
        values (new.id)
        on conflict (user_id) do nothing;
    end if;

    return new;
end;
$$;

revoke all on function public.create_student_profile() from public, anon, authenticated;

create trigger create_student_profile_after_signup
after insert on auth.users
for each row execute function public.create_student_profile();

create table public.conversations (
    id uuid primary key default gen_random_uuid(),
    student_id uuid not null references public.profiles (id) on delete cascade,
    lecturer_id uuid not null references public.profiles (id) on delete cascade,
    created_at timestamptz not null default now(),
    constraint conversations_distinct_participants
        check (student_id <> lecturer_id),
    constraint conversations_one_per_pair
        unique (student_id, lecturer_id)
);

create table public.messages (
    id uuid primary key default gen_random_uuid(),
    conversation_id uuid not null
        references public.conversations (id) on delete cascade,
    sender_id uuid not null references public.profiles (id) on delete cascade,
    body text not null
        check (char_length(trim(body)) between 1 and 4000),
    created_at timestamptz not null default now()
);

create table public.class_announcements (
    id uuid primary key default gen_random_uuid(),
    lecturer_id uuid not null references public.profiles (id) on delete cascade,
    course text not null
        check (char_length(trim(course)) between 1 and 100),
    title text not null
        check (char_length(trim(title)) between 1 and 120),
    message text not null
        check (char_length(trim(message)) between 1 and 2000),
    created_at timestamptz not null default now()
);

create table public.course_assignments (
    id uuid primary key default gen_random_uuid(),
    lecturer_id uuid not null references public.profiles (id) on delete cascade,
    course text not null
        check (char_length(trim(course)) between 1 and 100),
    title text not null
        check (char_length(trim(title)) between 1 and 120),
    due_date date,
    file_path text not null unique,
    file_name text not null
        check (char_length(trim(file_name)) between 1 and 255),
    created_at timestamptz not null default now()
);

create index conversations_student_created_idx
    on public.conversations (student_id, created_at desc);
create index conversations_lecturer_created_idx
    on public.conversations (lecturer_id, created_at desc);
create index messages_conversation_created_idx
    on public.messages (conversation_id, created_at);
create index class_announcements_created_idx
    on public.class_announcements (created_at desc);
create index course_assignments_created_idx
    on public.course_assignments (created_at desc);

alter table public.profiles enable row level security;
alter table public.lecturer_applications enable row level security;
alter table public.conversations enable row level security;
alter table public.messages enable row level security;
alter table public.class_announcements enable row level security;
alter table public.course_assignments enable row level security;

grant select on public.profiles to authenticated;
revoke update on public.profiles from authenticated;
grant update (full_name) on public.profiles to authenticated;
grant select on public.lecturer_applications to authenticated;

grant select, insert on public.conversations to authenticated;
grant select, insert on public.messages to authenticated;
grant select on public.class_announcements to anon, authenticated;
grant insert, delete on public.class_announcements to authenticated;
grant select, insert, delete on public.course_assignments to authenticated;

create policy "Users can view their lecturer application"
on public.lecturer_applications for select to authenticated
using (user_id = (select auth.uid()));

create policy "Signed-in users can view campus profiles"
on public.profiles for select to authenticated
using (true);

create policy "Users can update their own profile name"
on public.profiles for update to authenticated
using (id = (select auth.uid()))
with check (id = (select auth.uid()));

create policy "Participants can view their conversations"
on public.conversations for select to authenticated
using (
    (select auth.uid()) = student_id
    or (select auth.uid()) = lecturer_id
);

create policy "Students and lecturers can start direct conversations"
on public.conversations for insert to authenticated
with check (
    ((select auth.uid()) = student_id or (select auth.uid()) = lecturer_id)
    and exists (
        select 1 from public.profiles student
        where student.id = student_id and student.role = 'student'
    )
    and exists (
        select 1 from public.profiles lecturer
        where lecturer.id = lecturer_id and lecturer.role = 'lecturer'
    )
);

create policy "Participants can read conversation messages"
on public.messages for select to authenticated
using (
    exists (
        select 1 from public.conversations conversation
        where conversation.id = conversation_id
          and (
              conversation.student_id = (select auth.uid())
              or conversation.lecturer_id = (select auth.uid())
          )
    )
);

create policy "Participants can send messages as themselves"
on public.messages for insert to authenticated
with check (
    sender_id = (select auth.uid())
    and exists (
        select 1 from public.conversations conversation
        where conversation.id = conversation_id
          and (
              conversation.student_id = (select auth.uid())
              or conversation.lecturer_id = (select auth.uid())
          )
    )
);

create policy "Campus visitors can read class announcements"
on public.class_announcements for select to anon, authenticated
using (true);

create policy "Approved lecturers can post class announcements"
on public.class_announcements for insert to authenticated
with check (
    lecturer_id = (select auth.uid())
    and exists (
        select 1 from public.profiles lecturer
        where lecturer.id = (select auth.uid())
          and lecturer.role = 'lecturer'
    )
);

create policy "Lecturers can delete their own class announcements"
on public.class_announcements for delete to authenticated
using (
    lecturer_id = (select auth.uid())
    and exists (
        select 1 from public.profiles lecturer
        where lecturer.id = (select auth.uid())
          and lecturer.role = 'lecturer'
    )
);

create policy "Signed-in campus members can view assignments"
on public.course_assignments for select to authenticated
using (true);

create policy "Approved lecturers can upload assignments"
on public.course_assignments for insert to authenticated
with check (
    lecturer_id = (select auth.uid())
    and exists (
        select 1 from public.profiles lecturer
        where lecturer.id = (select auth.uid())
          and lecturer.role = 'lecturer'
    )
);

create policy "Lecturers can delete their own assignments"
on public.course_assignments for delete to authenticated
using (
    lecturer_id = (select auth.uid())
    and exists (
        select 1 from public.profiles lecturer
        where lecturer.id = (select auth.uid())
          and lecturer.role = 'lecturer'
    )
);

insert into storage.buckets (id, name, public, file_size_limit)
values ('assignments', 'assignments', false, 10485760)
on conflict (id) do update
set public = false,
    file_size_limit = excluded.file_size_limit;

create policy "Signed-in campus members can download assignments"
on storage.objects for select to authenticated
using (bucket_id = 'assignments');

create policy "Approved lecturers can upload assignment files"
on storage.objects for insert to authenticated
with check (
    bucket_id = 'assignments'
    and (storage.foldername(name))[1] = (select auth.uid())::text
    and exists (
        select 1 from public.profiles lecturer
        where lecturer.id = (select auth.uid())
          and lecturer.role = 'lecturer'
    )
);

create policy "Lecturers can delete their own assignment files"
on storage.objects for delete to authenticated
using (
    bucket_id = 'assignments'
    and (storage.foldername(name))[1] = (select auth.uid())::text
    and exists (
        select 1 from public.profiles lecturer
        where lecturer.id = (select auth.uid())
          and lecturer.role = 'lecturer'
    )
);

do $$
begin
    if exists (
        select 1 from pg_publication where pubname = 'supabase_realtime'
    ) and not exists (
        select 1 from pg_publication_tables
        where pubname = 'supabase_realtime'
          and schemaname = 'public'
          and tablename = 'messages'
    ) then
        execute 'alter publication supabase_realtime add table public.messages';
    end if;
end
$$;
