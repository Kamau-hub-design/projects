import { useState } from 'react'
import { formatPrice } from '../data/products.js'

function Checkout({ cart, profile, onNavigate, onCheckout }) {
  const [status, setStatus] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const subtotal = cart.reduce((total, item) => total + item.price * item.quantity, 0)

  async function submitOrder(event) {
    event.preventDefault()
    setStatus('')
    setSubmitting(true)
    try {
      await onCheckout()
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Checkout could not be started. Please try again.')
    } finally {
      setSubmitting(false)
    }
  }

  if (!cart.length) {
    return (
      <main className="content-page checkout-empty">
        <span className="eyebrow">READY WHEN YOU ARE</span>
        <h1>Your bag is empty.</h1>
        <p>Add a little something before heading to checkout.</p>
        <button className="primary-button" onClick={() => onNavigate('/products')}>Browse the collection</button>
      </main>
    )
  }

  return (
    <main className="shop-section checkout-page">
      <div className="section-heading"><div><span className="eyebrow">JUST A FEW DETAILS</span><h1 className="page-title">A good thing is <span>on its way.</span></h1></div></div>
      <div className="checkout-layout">
        <form className="checkout-form" onSubmit={submitOrder}>
          <section className="checkout-form-section">
            <span className="eyebrow">01 — YOUR DETAILS</span>
            <p className="checkout-customer">{profile.name}<br />{profile.email}</p>
          </section>
          <div className="payment-demo" role="note"><strong>Secure Stripe checkout</strong><span>Payment and shipping details are collected securely by Stripe. Final taxes and delivery charges are shown before payment.</span></div>
          {status && <p className="account-status" role="alert">{status}</p>}
          <button className="checkout-button" type="submit" disabled={submitting}>{submitting ? 'Opening secure checkout…' : 'Continue to secure checkout'} <span aria-hidden="true">→</span></button>
          <button className="continue-shopping checkout-back" type="button" onClick={() => onNavigate('/cart')}>← Back to your bag</button>
        </form>
        <aside className="checkout-summary">
          <h2>Your order</h2>
          {cart.map((item) => <div className="checkout-line" key={item.cartId}><span>{item.name}{item.variant && <small> · {item.variant}</small>} <small>× {item.quantity}</small></span><span>{formatPrice(item.price * item.quantity)}</span></div>)}
          <div className="checkout-line"><span>Subtotal</span><span>{formatPrice(subtotal)}</span></div>
          <div className="checkout-line"><span>Shipping and taxes</span><span>Calculated at checkout</span></div>
          <div className="checkout-total"><strong>Subtotal</strong><strong>{formatPrice(subtotal)}</strong></div>
        </aside>
      </div>
    </main>
  )
}

export default Checkout