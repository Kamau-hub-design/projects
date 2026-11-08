import { getAdminClient, getStripeClient, json } from '../server/backend.js'

export const config = { api: { bodyParser: false } }

async function readRawBody(request) {
  const chunks = []
  for await (const chunk of request) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
  return Buffer.concat(chunks)
}

export default async function handler(request, response) {
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST')
    return json(response, 405, { error: 'Method not allowed.' })
  }

  const signature = request.headers['stripe-signature']
  const secret = process.env.STRIPE_WEBHOOK_SECRET
  if (!signature || !secret) return json(response, 400, { error: 'Webhook configuration is missing.' })

  let event
  try {
    const rawBody = await readRawBody(request)
    event = getStripeClient().webhooks.constructEvent(rawBody, signature, secret)
  } catch (error) {
    console.error('Stripe webhook signature verification failed:', error.message)
    return json(response, 400, { error: 'Invalid webhook signature.' })
  }

  try {
    const supabase = getAdminClient()
    if (event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded') {
      const session = event.data.object
      if (session.payment_status !== 'paid' || !session.metadata?.order_id || !session.metadata?.user_id) {
        return json(response, 200, { received: true })
      }
      const { data: order, error: orderError } = await supabase
        .from('orders')
        .select('id,status,subtotal_cents,shipping_cents')
        .eq('id', session.metadata.order_id)
        .eq('user_id', session.metadata.user_id)
        .eq('stripe_checkout_session_id', session.id)
        .maybeSingle()
      if (orderError) throw orderError
      if (!order) return json(response, 200, { received: true })
      if (order.status === 'paid') return json(response, 200, { received: true })
      if (order.status !== 'pending'
        || session.currency !== 'usd'
        || session.amount_subtotal !== order.subtotal_cents
        || session.total_details?.amount_shipping !== order.shipping_cents
        || session.amount_total < order.subtotal_cents + order.shipping_cents) {
        throw new Error('Stripe session amounts do not match the stored order.')
      }
      const { error } = await supabase
        .from('orders')
        .update({
          status: 'paid',
          tax_cents: session.total_details?.amount_tax || 0,
          total_cents: session.amount_total,
          stripe_payment_intent_id: session.payment_intent,
          shipping_details: session.shipping_details,
        })
        .eq('id', session.metadata.order_id)
        .eq('user_id', session.metadata.user_id)
        .eq('stripe_checkout_session_id', session.id)
        .eq('status', 'pending')
      if (error) throw error
    } else if (event.type === 'checkout.session.expired') {
      const session = event.data.object
      if (session.metadata?.order_id && session.metadata?.user_id) {
        const { error } = await supabase
          .from('orders')
          .update({ status: 'cancelled' })
          .eq('id', session.metadata.order_id)
          .eq('user_id', session.metadata.user_id)
          .eq('stripe_checkout_session_id', session.id)
          .eq('status', 'pending')
        if (error) throw error
      }
    }
    return json(response, 200, { received: true })
  } catch (error) {
    console.error('Stripe webhook processing failed:', error.message)
    return json(response, 500, { error: 'Webhook processing failed.' })
  }
}
