import { formatPrice } from '../data/products.js'

const navigationItems = [
  { label: 'Overview', path: '/admin', icon: 'overview' },
  { label: 'Orders', path: '/admin/orders', icon: 'orders' },
  { label: 'Products', path: '/admin/products', icon: 'products' },
]

function DashboardIcon({ name }) {
  const icons = {
    overview: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>,
    orders: <><path d="M5 8h14l1 13H4L5 8Z" /><path d="M9 8a3 3 0 0 1 6 0" /></>,
    products: <><path d="m12 3 9 5-9 5-9-5 9-5Z" /><path d="m3 12 9 5 9-5M3 16l9 5 9-5" /></>,
    store: <><path d="M3 10h18l-2-6H5l-2 6Z" /><path d="M5 10v10h14V10M9 20v-6h6v6" /></>,
    signout: <><path d="M10 17l5-5-5-5M15 12H3" /><path d="M12 3h7a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-7" /></>,
    ordersMetric: <><path d="M5 8h14l1 13H4L5 8Z" /><path d="M9 8a3 3 0 0 1 6 0" /></>,
    revenue: <><path d="M12 2v20M17 6.5a4 4 0 0 0-4-2.5h-2a3.5 3.5 0 0 0 0 7h2a3.5 3.5 0 0 1 0 7h-2A4 4 0 0 1 7 15.5" /></>,
    pending: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
    catalog: <><path d="m12 3 9 5-9 5-9-5 9-5Z" /><path d="m3 12 9 5 9-5" /></>,
  }

  return (
    <svg aria-hidden="true" width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      {icons[name]}
    </svg>
  )
}

function AdminDashboard({ orders, productCount, customers = {}, onNavigate, onLogout }) {
  const paidOrders = orders.filter((order) => order.status === 'Paid')
  const revenue = paidOrders.reduce((total, order) => total + order.total, 0)
  const pendingOrders = orders.filter((order) => order.status === 'Payment pending').length
  const otherOrders = orders.length - paidOrders.length - pendingOrders
  const paymentBreakdown = [
    { label: 'Paid', count: paidOrders.length, color: 'paid' },
    { label: 'Awaiting payment', count: pendingOrders, color: 'pending' },
    { label: 'Other', count: otherOrders, color: 'other' },
  ]

  return (
    <main className="shop-section admin-dashboard admin-marketplace">
      <div className="admin-marketplace-layout">
        <aside className="admin-marketplace-sidebar">
          <div className="admin-sidebar-brand">
            <span className="admin-brand-mark">S</span>
            <span>STORE<span className="admin-brand-caption">SELLER CENTER</span></span>
          </div>
          <span className="admin-sidebar-label">WORKSPACE</span>
          <nav className="admin-dashboard-nav" aria-label="Admin navigation">
            {navigationItems.map((item) => (
              <button
                className={`admin-dashboard-nav-link${item.path === '/admin' ? ' is-active' : ''}`}
                type="button"
                key={item.path}
                aria-current={item.path === '/admin' ? 'page' : undefined}
                onClick={() => onNavigate(item.path)}
              >
                <DashboardIcon name={item.icon} />
                <span>{item.label}</span>
                {item.path === '/admin/orders' && orders.length > 0 && <span className="admin-nav-count">{orders.length}</span>}
              </button>
            ))}
          </nav>
          <div className="admin-sidebar-bottom">
            <button className="admin-dashboard-nav-link" type="button" onClick={() => onNavigate('/')}>
              <DashboardIcon name="store" /><span>View storefront</span>
            </button>
            <button className="admin-dashboard-nav-link admin-signout-link" type="button" onClick={onLogout}>
              <DashboardIcon name="signout" /><span>Sign out</span>
            </button>
          </div>
        </aside>

        <div className="admin-marketplace-content">
          <header className="admin-dashboard-topbar">
            <div>
              <span className="admin-topbar-eyebrow">SELLER CENTER <span>/</span> OVERVIEW</span>
              <h1>Store overview</h1>
              <p>Here’s what’s happening with your store today.</p>
            </div>
            <div className="admin-topbar-date">
              <span className="admin-online-dot" />
              <span>Store is live</span>
            </div>
          </header>

          <section className="admin-marketplace-stats" aria-label="Store performance">
            <article className="admin-marketplace-stat">
              <div className="admin-stat-icon stat-orange"><DashboardIcon name="ordersMetric" /></div>
              <span className="admin-stat-label">Total orders</span>
              <strong>{orders.length}</strong>
              <span className="admin-stat-note">Orders placed in your store</span>
            </article>
            <article className="admin-marketplace-stat">
              <div className="admin-stat-icon stat-green"><DashboardIcon name="revenue" /></div>
              <span className="admin-stat-label">Paid revenue</span>
              <strong>{formatPrice(revenue)}</strong>
              <span className="admin-stat-note">{paidOrders.length} successfully paid</span>
            </article>
            <article className="admin-marketplace-stat">
              <div className="admin-stat-icon stat-blue"><DashboardIcon name="pending" /></div>
              <span className="admin-stat-label">Awaiting payment</span>
              <strong>{pendingOrders}</strong>
              <span className="admin-stat-note">Payment confirmation pending</span>
            </article>
            <article className="admin-marketplace-stat">
              <div className="admin-stat-icon stat-purple"><DashboardIcon name="catalog" /></div>
              <span className="admin-stat-label">Active products</span>
              <strong>{productCount}</strong>
              <span className="admin-stat-note">Available on your storefront</span>
            </article>
          </section>

          <div className="admin-overview-grid">
            <section className="admin-marketplace-panel admin-recent-orders">
              <div className="admin-marketplace-panel-heading">
                <div><h2>Recent orders</h2><p>Keep track of your latest sales and fulfillment.</p></div>
                <button className="admin-marketplace-link" type="button" onClick={() => onNavigate('/admin/orders')}>All orders <span>→</span></button>
              </div>
              {orders.length ? (
                <div className="admin-marketplace-table-wrap">
                  <table className="admin-marketplace-table">
                    <thead>
                      <tr><th>ORDER</th><th>CUSTOMER</th><th>DATE</th><th>PAYMENT</th><th>FULFILLMENT</th><th>TOTAL</th></tr>
                    </thead>
                    <tbody>
                      {orders.slice(0, 8).map((order) => (
                        <tr key={order.id}>
                          <td><strong>#{order.id.slice(0, 8).toUpperCase()}</strong><small>{order.items.reduce((count, item) => count + item.quantity, 0)} items</small></td>
                          <td>{customers[order.user_id] || 'Customer'}</td>
                          <td>{order.date}</td>
                          <td><span className={`admin-payment-badge ${order.status === 'Paid' ? 'is-paid' : order.status === 'Payment pending' ? 'is-pending' : 'is-other'}`}>{order.status}</span></td>
                          <td><span className="admin-fulfillment-label">{(order.fulfillment_status || 'unfulfilled').replaceAll('_', ' ')}</span></td>
                          <td><strong>{formatPrice(order.total)}</strong></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="admin-marketplace-empty">
                  <span className="admin-empty-icon"><DashboardIcon name="ordersMetric" /></span>
                  <strong>No orders yet</strong>
                  <p>Your new orders will show up here.</p>
                </div>
              )}
            </section>

            <div className="admin-overview-side">
              <section className="admin-marketplace-panel admin-payment-overview">
                <div className="admin-marketplace-panel-heading">
                  <div><h2>Payment overview</h2><p>Order payment status</p></div>
                </div>
                <div className="admin-payment-summary"><strong>{orders.length}</strong><span>total orders</span></div>
                <div className="admin-payment-breakdown">
                  {paymentBreakdown.map((item) => {
                    const percentage = orders.length ? Math.round((item.count / orders.length) * 100) : 0
                    return (
                      <div className="admin-payment-item" key={item.label}>
                        <div className="admin-payment-label"><span><i className={`payment-dot ${item.color}`} />{item.label}</span><strong>{item.count}</strong></div>
                        <div className="admin-payment-track" role="progressbar" aria-label={`${item.label} orders`} aria-valuenow={percentage} aria-valuemin="0" aria-valuemax="100">
                          <span className={item.color} style={{ width: `${percentage}%` }} />
                        </div>
                      </div>
                    )
                  })}
                </div>
              </section>

              <section className="admin-marketplace-panel admin-catalog-card">
                <div className="admin-catalog-icon"><DashboardIcon name="catalog" /></div>
                <div><span className="admin-stat-label">YOUR CATALOG</span><h2>Manage products</h2><p>Add new items, update details, or archive products.</p></div>
                <button className="admin-catalog-button" type="button" onClick={() => onNavigate('/admin/products')}>Open catalog <span>→</span></button>
              </section>
            </div>
          </div>

          <p className="admin-security-note">Admin access is managed through your account. Only paid orders can be moved through fulfillment.</p>
        </div>
      </div>
    </main>
  )
}

export default AdminDashboard
