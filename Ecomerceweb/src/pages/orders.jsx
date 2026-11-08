import { formatPrice } from '../data/products.js'

function Orders({ orders, onNavigate, paymentSuccess = false }) {
  return (
    <main className="shop-section orders-page">
      <div className="section-heading"><div><span className="eyebrow">YOUR STUDIO GOODS</span><h1 className="page-title">Order <span>notes.</span></h1></div></div>
      {paymentSuccess && <p className="payment-confirmation" role="status">Thanks for your order. Payment confirmation will appear here as soon as Stripe finishes processing.</p>}
      {orders.length ? (
        <div className="orders-list">
          {orders.map((order) => (
            <article className="order-card" key={order.id}>
              <div className="order-card-heading"><div><span className="eyebrow">ORDER {order.id}</span><p>Placed {order.date}</p></div><span className="order-status">{order.status}</span></div>
              <p className="customer-fulfillment">Fulfillment: <strong>{(order.fulfillment_status || 'unfulfilled').replaceAll('_', ' ')}</strong></p>
              <div className="order-items">{order.items.map((item) => <p key={`${item.id}-${item.variant || ''}`}>{item.name}{item.variant && <span> · {item.variant}</span>} <span>× {item.quantity}</span></p>)}</div>
              <div className="order-total"><span>Order total</span><strong>{formatPrice(order.total)}</strong></div>
            </article>
          ))}
        </div>
      ) : (
        <div className="empty-orders">
          <span className="eyebrow">NO ORDERS JUST YET</span>
          <h2>Your next favorite is out there.</h2>
          <p>Once you place an order, you’ll find its details here.</p>
          <button className="primary-button" onClick={() => onNavigate('/products')}>Find your favorites</button>
        </div>
      )}
    </main>
  )
}

export default Orders