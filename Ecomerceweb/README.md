# Studio Goods

A responsive React storefront with Supabase authentication and order storage, Stripe Checkout, and Vercel serverless API functions.

## Local development

1. Install Node.js 20.19+ or 22.12+ and npm.
2. Install dependencies with `npm install`.
3. Copy `.env.example` to `.env.local` and fill in the Supabase and Stripe values. Use Stripe test keys and a test webhook secret for local development.
4. Run `npm run dev`.

The storefront runs at `http://localhost:5173`. Vite serves the frontend only; `/api/*` checkout and webhook functions run on Vercel. Test those endpoints in a Vercel preview deployment or with the Vercel CLI (`vercel dev`).

## Supabase setup

1. Create a Supabase project.
2. In the SQL Editor, run both migrations in order: [`20261108122000_initial_schema.sql`](./supabase/migrations/20261108122000_initial_schema.sql), then [`20261108130000_admin_management.sql`](./supabase/migrations/20261108130000_admin_management.sql). The second migration seeds the initial catalog and adds persisted product management, fulfillment status, and admin access policies.
3. In Authentication settings, configure the site URL and allowed redirect URLs for local development and the production domain. Allow `/dashboard` for email confirmation and `/reset-password` for password resets.
4. Set `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` (or the project's publishable key) from the project's API settings.
5. To grant admin access, use a trusted server-side Supabase Auth Admin API process to set the user's `app_metadata` to include `{ "role": "admin" }`. The service-role key must never be exposed in browser code or given to customers. The user must sign in again to receive a token with the updated role.

The admin dashboard is at `/admin`, with `/admin/orders` for order and fulfillment management and `/admin/products` for creating, editing, and archiving catalog products. Supabase row-level security allows admins to manage the catalog and update fulfillment while regular customers can only read their own orders. Checkout reads live prices and availability from the Supabase catalog; archived products are no longer available for purchase.

## Stripe setup

1. Configure a Stripe account and enable Stripe Tax for automatic tax calculation.
2. Add the Stripe secret key as `STRIPE_SECRET_KEY` in Vercel (and `.env.local` when testing server functions locally).
3. Register a Stripe webhook at `https://YOUR_DOMAIN/api/stripe-webhook` for `checkout.session.completed`, `checkout.session.async_payment_succeeded`, and `checkout.session.expired`.
4. Set the signing secret as `STRIPE_WEBHOOK_SECRET`. Use the endpoint's test-mode signing secret for test deployments.

Checkout currently supports USD and shipping addresses in the United States. Shipping is $6.95 below $75 and free at $75 or more; Stripe collects the address, payment, and applicable automatic tax.

## Vercel deployment

1. Import the project into Vercel and set the project root to this directory (the directory containing `package.json`).
2. Set these environment variables for Preview and Production as appropriate:
   - `VITE_SUPABASE_URL`
   - `VITE_SUPABASE_ANON_KEY`
   - `SUPABASE_URL`
   - `SUPABASE_SERVICE_ROLE_KEY` (server only)
   - `STRIPE_SECRET_KEY` (server only)
   - `STRIPE_WEBHOOK_SECRET` (server only)
   - `APP_URL` (the public HTTPS origin, with no trailing slash)
3. Deploy. Add the final Vercel domain to Supabase's allowed redirect URLs, and register the Stripe webhook against the final domain.
4. Verify account registration, email confirmation, sign-in, admin permissions, checkout, and webhook-driven order status using Stripe test mode before switching to live keys.

Do not commit `.env.local` or provider secrets. `.env.example` contains placeholders only.

## Pages

- `/` — storefront home and featured products
- `/products` and `/products/:id` — product catalog and details
- `/cart` and `/checkout` — shopping bag and hosted Stripe checkout
- `/login`, `/register`, and `/reset-password` — Supabase account flows
- `/dashboard`, `/profile`, and `/orders` — customer account pages
- `/admin` — admin store overview
- `/admin/orders` — search orders, inspect items and shipping details, and update paid-order fulfillment
- `/admin/products` — add, edit, archive, and restore products

## Checks

```sh
npm run lint
npm run build
```
