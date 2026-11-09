import { useEffect, useMemo, useState } from 'react'
import { formatPrice } from '../data/products.js'

const fulfillmentOptions = [
  ['unfulfilled', 'Unfulfilled'],
  ['processing', 'Processing'],
  ['shipped', 'Shipped'],
  ['delivered', 'Delivered'],
  ['returned', 'Returned'],
]

function TrackingEditor({ order, busy, onSave }) {
  const [carrier, setCarrier] = useState(order.tracking_carrier || '')
  const [number, setNumber] = useState(order.tracking_number || '')
  const [url, setUrl] = useState(order.tracking_url || '')

  useEffect(() => {
    setCarrier(order.tracking_carrier || '')
    setNumber(order.tracking_number || '')
    setUrl(order.tracking_url || '')
  }, [order.tracking_carrier, order.tracking_number, order.tracking_url])

  async function submit(event) {
    event.preventDefault()
    await onSave(order.id, { carrier, number, url })
  }

  return (
    <form className="admin-tracking-form" onSubmit={submit}>
      <label>Carrier<input value={carrier} maxLength={100} onChange={(event) => setCarrier(event.target.value)} placeholder="e.g. UPS" /></label>
      <label>Tracking number<input value={number} maxLength={120} onChange={(event) => setNumber(event.target.value)} placeholder="Tracking number" /></label>
      <label>Tracking URL<input type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://carrier.example/track/…" /></label>
      <button className="account-submit" type="submit" disabled={busy || order.status !== 'Paid'}>{busy ? 'Saving…' : 'Save tracking'}</button>
    </form>
  )
}

function ManageOrders({ orders, customers, onFulfillmentChange, onTrackingChange, onNavigate }) {
  const [filter, setFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [busyOrder, setBusyOrder] = useState('')
  const [busyTrackingOrder, setBusyTrackingOrder] = useState('')
  const [message, setMessage] = useState('')

  const visibleOrders = useMemo(() => orders.filter((order) => {
    const matchesStatus = filter === 'all' || order.fulfillment_status === filter
    const customer = customers[order.user_id] || ''
    const matchesSearch = `${order.id} ${customer} ${order.status}`.toLowerCase().includes(search.trim().toLowerCase())
    return matchesStatus && matchesSearch
  }), [customers, filter, orders, search])

  async function updateFulfillment(orderId, status) {
    setBusyOrder(orderId)
    setMessage('')
    try {
      await onFulfillmentChange(orderId, status)
      setMessage('Fulfillment status updated.')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Could not update this order.')
    } finally {
      setBusyOrder('')
    }
  }

  async function updateTracking(orderId, tracking) {
    setBusyTrackingOrder(orderId)
    setMessage('')
    try {
      await onTrackingChange(orderId, tracking)
      setMessage('Shipment tracking updated.')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Could not update shipment tracking.')
    } finally {
      setBusyTrackingOrder('')
    }
  }

  return (
    <main className="shop-section admin-dashboard">
      <button className="back-link" onClick={() => onNavigate('/admin')}>← Admin overview</button>
      <div className="dashboard-welcome admin-page-heading">
        <div><span className="eyebrow">STUDIO GOODS · ADMIN</span><h1>Manage <em>orders.</em></h1><p>Review payment and update order fulfillment.</p></div>
      </div>
      <section className="dashboard-panel admin-orders-panel">
        <div className="admin-management-toolbar">
          <label className="products-search"><span className="visually-hidden">Search orders</span><input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search order or customer..." /></label>
          <label className="admin-filter-label">FULFILLMENT
            <select value={filter} onChange={(event) => setFilter(event.target.value)}>
              <option value="all">All statuses</option>
              {fulfillmentOptions.map(([value, label]) => <option value={value} key={value}>{label}</option>)}
            </select>
          </label>
          <span className="item-count">{visibleOrders.length} orders</span>
        </div>
        {message && <p className="admin-feedback" role="status">{message}</p>}
        {visibleOrders.length ? (
          <div className="admin-orders-table">
            <div className="admin-order-row admin-manage-order-row admin-order-head"><span>ORDER / CUSTOMER</span><span>DATE</span><span>PAYMENT</span><span>FULFILLMENT</span><span>TOTAL</span></div>
            {visibleOrders.map((order) => (
              <article className="admin-order-row admin-manage-order-row" key={order.id}>
                <span className="admin-order-customer"><strong>{order.id.slice(0, 8).toUpperCase()}</strong><small>{customers[order.user_id] || 'Customer'}</small></span>
                <span>{order.date}</span>
                <span className={`order-status order-status-${order.status.toLowerCase().replaceAll(' ', '-')}`}>{order.status}</span>
                <label className="visually-hidden" htmlFor={`fulfillment-${order.id}`}>Fulfillment status for order {order.id}</label>
                <select id={`fulfillment-${order.id}`} className="admin-fulfillment-select" value={order.fulfillment_status || 'unfulfilled'} disabled={busyOrder === order.id || order.status !== 'Paid'} onChange={(event) => updateFulfillment(order.id, event.target.value)}>
                  {fulfillmentOptions.map(([value, label]) => <option value={value} key={value}>{label}</option>)}
                </select>
                <strong>{formatPrice(order.total)}</strong>
                <details className="admin-order-details"><summary>Order items</summary><div>{order.items.map((item) => <p key={`${item.id}-${item.variant || ''}`}>{item.name}{item.variant && ` · ${item.variant}`} × {item.quantity}</p>)}</div></details>
                {order.shipping_details?.address && <details className="admin-order-details"><summary>Shipping address</summary><div><p>{order.shipping_details.name}</p><p>{[order.shipping_details.address.line1, order.shipping_details.address.line2, [order.shipping_details.address.city, order.shipping_details.address.state, order.shipping_details.address.postal_code].filter(Boolean).join(', '), order.shipping_details.address.country].filter(Boolean).join(' · ')}</p></div></details>}
                <details className="admin-order-details admin-tracking-details">
                  <summary>{order.tracking_number ? 'Edit shipment tracking' : 'Add shipment tracking'}</summary>
                  <TrackingEditor order={order} busy={busyTrackingOrder === order.id} onSave={updateTracking} />
                </details>
              </article>
            ))}
          </div>
        ) : <div className="dashboard-empty"><p>No orders match these filters.</p></div>}
      </section>
    </main>
  )
}

export default ManageOrders