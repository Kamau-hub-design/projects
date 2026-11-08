import { getAdminClient, getAuthenticatedUser, getStripeClient, json } from '../server/backend.js'

const allowedCountries = ['US']

export default async function handler(request, response) {
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST')
    return json(response, 405, { error: 'Method not allowed.' })
  }

  try {
    const user = await getAuthenticatedUser(request)
    if (!user) return json(response, 401, { error: 'Sign in before starting checkout.' })

    const items = request.body?.items
    if (!Array.isArray(items) || items.length === 0 || items.length > 50) {
      return json(response, 400, { error: 'Your bag is empty or contains too many different items.' })
    }

    const productIds = items.map((item) => Number(item?.id))
    if (productIds.some((id) => !Number.isInteger(id) || id < 1)) {
      return json(response, 400, { error: 'A product or quantity in your bag is invalid. Refresh your bag and try again.' })
    }

    const supabase = getAdminClient()
    const { data: catalogRows, error: catalogError } = await supabase.from('products')
      .select('id,name,category,price_cents,color')
      .in('id', [...new Set(productIds)])
      .eq('is_active', true)
    if (catalogError) throw catalogError
    const catalog = new Map((catalogRows || []).map((product) => [product.id, product]))

    const lineItems = []
    const orderItems = []
    let subtotal = 0
    for (const item of items) {
      const product = catalog.get(Number(item.id))
      const quantity = Number(item.quantity)
      const validVariant = product?.category === 'Clothing' ? ['Size S', 'Size M', 'Size L'].includes(item.variant) : !item.variant
      if (!product || !Number.isInteger(quantity) || quantity < 1 || quantity > 10 || !validVariant) {
        return json(response, 400, { error: 'A product or quantity in your bag is invalid. Refresh your bag and try again.' })
      }
      subtotal += product.price_cents * quantity
      orderItems.push({
        id: product.id,
        name: product.name,
        price: product.price_cents / 100,
        quantity,
        variant: item.variant || '',
      })
      lineItems.push({
        price_data: {
          currency: 'usd',
          product_data: { name: product.name, description: item.variant || product.color },
          unit_amount: product.price_cents,
        },
        quantity,
      })
    }

    const shippingCents = subtotal >= 7500 ? 0 : 695

    const { data: order, error: insertError } = await supabase
      .from('orders')
      .insert({
        user_id: user.id,
        status: 'pending',
        currency: 'usd',
        subtotal_cents: subtotal,
        shipping_cents: shippingCents,
        total_cents: subtotal + shippingCents,
        items: orderItems,
      })
      .select('id')
      .single()

    if (insertError) {
      console.error('Unable to create pending order:', insertError.message)
      return json(response, 503, { error: 'We couldn’t save your order. Please try again later.' })
    }

    try {
      const stripe = getStripeClient()
      const origin = process.env.APP_URL
      if (!origin || new URL(origin).protocol !== 'https:' && process.env.NODE_ENV === 'production') {
        throw new Error('APP_URL must be configured with the production HTTPS origin.')
      }
      const session = await stripe.checkout.sessions.create({
        mode: 'payment',
        payment_method_types: ['card'],
        customer_email: user.email,
        client_reference_id: order.id,
        metadata: { order_id: order.id, user_id: user.id },
        line_items: lineItems,
        billing_address_collection: 'required',
        shipping_address_collection: { allowed_countries: allowedCountries },
        shipping_options: [{
          shipping_rate_data: {
            type: 'fixed_amount',
            display_name: shippingCents ? 'Standard shipping' : 'Free shipping',
            fixed_amount: { amount: shippingCents, currency: 'usd' },
            delivery_estimate: {
              minimum: { unit: 'business_day', value: 3 },
              maximum: { unit: 'business_day', value: 7 },
            },
          },
        }],
        automatic_tax: { enabled: true },
        success_url: `${origin}/orders?checkout=success`,
        cancel_url: `${origin}/checkout?checkout=cancelled`,
      })

      const { error: updateError } = await supabase
        .from('orders')
        .update({ stripe_checkout_session_id: session.id })
        .eq('id', order.id)
        .eq('user_id', user.id)
      if (updateError) throw updateError

      return json(response, 200, { url: session.url })
    } catch (error) {
      await supabase.from('orders').update({ status: 'failed' }).eq('id', order.id).eq('user_id', user.id)
      throw error
    }
  } catch (error) {
    console.error('Checkout session creation failed:', error.message)
    return json(response, 503, { error: 'Checkout is temporarily unavailable. Please try again later.' })
  }
}
