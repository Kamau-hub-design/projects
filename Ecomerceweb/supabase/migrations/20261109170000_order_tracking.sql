alter table public.orders
  add column tracking_carrier text
    check (tracking_carrier is null or char_length(tracking_carrier) <= 100),
  add column tracking_number text
    check (tracking_number is null or char_length(tracking_number) <= 120),
  add column tracking_url text
    check (tracking_url is null or (char_length(tracking_url) <= 2048 and tracking_url ~ '^https://'));

grant update (tracking_carrier, tracking_number, tracking_url) on public.orders to authenticated;
