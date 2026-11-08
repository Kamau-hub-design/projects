create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'full_name', ''))
  on conflict (id) do nothing;
  return new;
end;
$$;

create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

create function public.update_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger profiles_updated_at
before update on public.profiles
for each row execute procedure public.update_updated_at();

create table public.favorites (
  user_id uuid not null references auth.users (id) on delete cascade,
  product_id integer not null check (product_id > 0),
  created_at timestamptz not null default now(),
  primary key (user_id, product_id)
);

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete restrict,
  status text not null default 'pending'
    check (status in ('pending', 'paid', 'cancelled', 'failed')),
  currency text not null default 'usd' check (currency = 'usd'),
  subtotal_cents integer not null check (subtotal_cents > 0),
  shipping_cents integer not null default 0 check (shipping_cents >= 0),
  tax_cents integer not null default 0 check (tax_cents >= 0),
  total_cents integer not null check (total_cents >= subtotal_cents),
  items jsonb not null check (jsonb_typeof(items) = 'array'),
  stripe_checkout_session_id text unique,
  stripe_payment_intent_id text,
  created_at timestamptz not null default now()
);

create index orders_user_created_at_idx on public.orders (user_id, created_at desc);

alter table public.profiles enable row level security;
alter table public.favorites enable row level security;
alter table public.orders enable row level security;

create policy "Users can read their profile"
on public.profiles for select
to authenticated
using ((select auth.uid()) = id);

create policy "Users can update their profile"
on public.profiles for update
to authenticated
using ((select auth.uid()) = id)
with check ((select auth.uid()) = id);

revoke all on public.profiles from anon, authenticated;
grant select, update (full_name) on public.profiles to authenticated;

create policy "Users can read their favorites"
on public.favorites for select
to authenticated
using ((select auth.uid()) = user_id);

create policy "Users can add their own favorites"
on public.favorites for insert
to authenticated
with check ((select auth.uid()) = user_id);

create policy "Users can remove their own favorites"
on public.favorites for delete
to authenticated
using ((select auth.uid()) = user_id);

revoke all on public.favorites from anon, authenticated;
grant select, insert, delete on public.favorites to authenticated;

create policy "Users can read their orders"
on public.orders for select
to authenticated
using ((select auth.uid()) = user_id);

create policy "Admins can read all orders"
on public.orders for select
to authenticated
using ((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

revoke all on public.orders from anon, authenticated;
grant select on public.orders to authenticated;
