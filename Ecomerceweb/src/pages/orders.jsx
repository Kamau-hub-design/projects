import { formatPrice } from '../data/products.js'

const fulfillmentSteps = ['unfulfilled', 'processing', 'shipped', 'delivered']

function Orders({ orders, orderId, onNavigate, paymentSuccess = false }) {
  const selectedOrder = orderId ? orders.find((order) => order.id === orderId) : null
  if (orderId) {
    if (!selectedOrder) {
      return (
        <main className="shop-section orders-page">
          <div className="empty-orders">
            <span className="eyebrow">ORDER NOT FOUND</span>
            <h1>This order isn’t available.</h1>
            <p>Check the order link or return to your order history.</p>
            <button className="primary-button" onClick={() => onNavigate('/orders')}>View all orders</button>
          </div>
        </main>
      )
    }

    const stepIndex = fulfillmentSteps.indexOf(selectedOrder.fulfillment_status || 'unfulfilled')
    return (
      <main className="shop-section orders-page">
        <button className="back-link" onClick={() => onNavigate('/orders')}>← All orders</button>
        <div className="section-heading"><div><span className="eyebrow">ORDER {selectedOrder.id}</span><h1 className="page-title">Track your <span>order.</span></h1></div></div>
        <article className="order-card order-tracking-card">
          <div className="order-card-heading"><div><span className="eyebrow">ORDER STATUS</span><p>Placed {selectedOrder.date}</p></div><span className="order-status">{selectedOrder.status}</span></div>
          <div className="tracking-progress" aria-label={`Fulfillment status: ${(selectedOrder.fulfillment_status || 'unfulfilled').replaceAll('_', ' ')}`}>
            {fulfillmentSteps.map((step, index) => (
              <div className={`tracking-step${index <= stepIndex ? ' is-complete' : ''}`} key={step}>
                <span aria-hidden="true">{index < stepIndex ? '✓' : index + 1}</span>
                <strong>{step.replaceAll('_', ' ')}</strong>
              </div>
            ))}
          </div>
          {selectedOrder.fulfillment_status === 'returned' && <p className="customer-fulfillment">Fulfillment: <strong>returned</strong></p>}
          {selectedOrder.tracking_number ? (
            <div className="tracking-shipment">
              <span className="eyebrow">SHIPMENT DETAILS</span>
              <p>{selectedOrder.tracking_carrier || 'Carrier'} · <strong>{selectedOrder.tracking_number}</strong></p>
              {selectedOrder.tracking_url && <a className="text-link" href={selectedOrder.tracking_url} target="_blank" rel="noreferrer">Track with carrier <span aria-hidden="true">↗</span></a>}
            </div>
          ) : (
            <p className="tracking-pending">Tracking details will appear here once your order has shipped.</p>
          )}
          <div className="order-items">{selectedOrder.items.map((item) => <p key={`${item.id}-${item.variant || ''}`}>{item.name}{item.variant && <span> · {item.variant}</span>} <span>× {item.quantity}</span></p>)}</div>
          <div className="order-total"><span>Order total</span><strong>{formatPrice(selectedOrder.total)}</strong></div>
        </article>
      </main>
    )
  }

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
              {order.tracking_number && <p className="customer-tracking">{order.tracking_carrier || 'Carrier'} tracking: <strong>{order.tracking_number}</strong></p>}
              <div className="order-items">{order.items.map((item) => <p key={`${item.id}-${item.variant || ''}`}>{item.name}{item.variant && <span> · {item.variant}</span>} <span>× {item.quantity}</span></p>)}</div>
              <div className="order-total"><span>Order total</span><strong>{formatPrice(order.total)}</strong></div>
              <button className="order-track-button" onClick={() => onNavigate(`/orders/${encodeURIComponent(order.id)}`)}>View order & tracking →</button>
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