# Kamau Warukari Portfolio

A static portfolio website for mobile and web application development, networking, and artificial intelligence projects.

## Run locally

Open `index.html` in a browser. The public portfolio works without a Supabase project; owner project management requires Supabase.

## Enable owner project management

1. Create a Supabase project and enable email/password authentication.
2. Create the owner's account in Supabase Auth.
3. Replace the owner email placeholder in `supabase-setup.sql` with the account email, then run the SQL in Supabase's SQL Editor.
4. Put the Supabase project URL, publishable/anon key, and owner email in `supabase-config.js`.
5. Host this folder on a static HTTPS host.

The website's public key is intended for browser use. Never put a Supabase service-role key or account password in this project. Row-level security lets anyone read project entries and allows only the configured owner to create, edit, or delete them.
