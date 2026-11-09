# Supabase setup

Messaging, lecturer accounts, class announcements, and shared assignments use
Supabase Auth, Postgres, row-level security, and private Storage.

1. Create a Supabase project and run [`messaging.sql`](./messaging.sql) in its
   SQL Editor.
2. In `script/script.js`, set `url` to the project's Project URL and `anonKey`
   to its **publishable/anon key** in the `supabaseConfig` object near the top
   of the file. Never put a `service_role` or secret key in this browser app.
3. Configure the Supabase Auth site URL and redirect URLs for the URL where
   Campusly will be hosted. Serve the app over HTTPS (or localhost during
   development), not by opening the HTML file directly.
4. Students can create accounts from the Messaging tab. Lecturer accounts are
   created from Lecturer Dashboard → Register as a lecturer. Confirm the
   lecturer's email before approval. New accounts remain students until an
   administrator approves them; registration never grants lecturer privileges.
5. To approve a lecturer, replace the example email and run the following in
   the Supabase SQL Editor:

   ```sql
   begin;

   update public.profiles
   set role = 'lecturer'
   where id = (
       select id from auth.users
       where lower(email) = lower('lecturer@university.example')
   )
   and exists (
       select 1 from public.lecturer_applications application
       where application.user_id = profiles.id
         and application.status = 'pending'
   );

   update public.lecturer_applications
   set status = 'approved'
   where user_id = (
       select id from auth.users
       where lower(email) = lower('lecturer@university.example')
   );

   commit;
   ```

   To reject an application instead, set its status to `rejected` using the
   applicant's `user_id`. Only trusted administrators should run approval
   queries. Do not grant users permission to update their own role or
   application status.
6. Approved lecturers can sign in to upload assignments (up to 10 MB) and post
   class announcements. Class announcements are readable in the Announcements
   tab. Assignment details and files are available to signed-in campus members;
   file objects remain in the private `assignments` bucket.

The directory shows only the opposite role: students can start conversations
with lecturers, and lecturers can start conversations with students. Database
row-level security restricts conversations and messages to their participants.
