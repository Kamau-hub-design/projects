import { createClient } from '@supabase/supabase-js'
import Stripe from 'stripe'

let adminClient
let stripeClient

export function getAdminClient() {
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error('Server Supabase environment is not configured.')
  }
  adminClient ??= createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  })
  return adminClient
}

export function getStripeClient() {
  if (!process.env.STRIPE_SECRET_KEY) throw new Error('Stripe is not configured.')
  stripeClient ??= new Stripe(process.env.STRIPE_SECRET_KEY)
  return stripeClient
}

export async function getAuthenticatedUser(request) {
  const authorization = request.headers.authorization || ''
  const match = authorization.match(/^Bearer (.+)$/i)
  if (!match) return null

  const { data: { user }, error } = await getAdminClient().auth.getUser(match[1])
  if (error || !user) return null
  return user
}

export function json(response, status, payload) {
  response.status(status).setHeader('Content-Type', 'application/json; charset=utf-8').end(JSON.stringify(payload))
}
