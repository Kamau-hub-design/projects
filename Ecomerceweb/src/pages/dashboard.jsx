import { formatPrice } from '../data/products.js'

function Dashboard({ profile, orders, favorites, products, cartCount, onNavigate, onLogout }) {
  const savedProducts = products.filter((product) => favorites.includes(product.id))
  const latestOrders = orders.slice(0, 3)

  return (
    <main className="shop-section dashboard-page">
      <div className="dashboard-welcome">
        <div><span className="eyebrow">YOUR STUDIO GOODS</span><h1>Good to have you, <em>{profile.name.split(' ')[0] || 'friend'}.</em></h1><p>Here’s a little home for your order notes and saved pieces.</p></div>
        <button className="dashboard-signout" onClick={onLogout}>Sign out</button>
      </div>
      <div className="dashboard-stats">
        <button className="dashboard-stat" onClick={() => onNavigate('/orders')}><span className="eyebrow">ORDER NOTES</span><strong>{orders.length}</strong><span>See your orders →</span></button>
        <button className="dashboard-stat" onClick={() => onNavigate('/products?filter=saved')}><span className="eyebrow">SAVED PIECES</span><strong>{favorites.length}</strong><span>Visit your saved list →</span></button>
        <button className="dashboard-stat" onClick={() => onNavigate('/cart')}><span className="eyebrow">IN YOUR BAG</span><strong>{cartCount}</strong><span>Take another look →</span></button>
      </div>
      <div className="dashboard-columns">
        <section className="dashboard-panel">
          <div className="dashboard-panel-heading"><div><span className="eyebrow">THE LATEST</span><h2>Order notes</h2></div><button className="text-link text-button" onClick={() => onNavigate('/orders')}>All orders →</button></div>
          {latestOrders.length ? latestOrders.map((order) => <article className="dashboard-order" key={order.id}><div><strong>{order.id}</strong><span>{order.date}</span></div><div><span>{order.items.length} {order.items.length === 1 ? 'piece' : 'pieces'}</span><strong>{formatPrice(order.total)}</strong></div><span className="order-status">{order.status}</span></article>) : <div className="dashboard-empty"><p>No orders just yet. Your next favorite is out there.</p><button className="text-link text-button" onClick={() => onNavigate('/products')}>Find your favorites →</button></div>}
        </section>
        <section className="dashboard-panel">
          <div className="dashboard-panel-heading"><div><span className="eyebrow">A LITTLE LIST FOR LATER</span><h2>Saved pieces</h2></div><button className="text-link text-button" onClick={() => onNavigate('/products?filter=saved')}>See all →</button></div>
          {savedProducts.length ? savedProducts.slice(0, 3).map((product) => <button className="dashboard-favorite" key={product.id} onClick={() => onNavigate(`/products/${product.id}`)}><img src={`https://images.unsplash.com/${product.image}?auto=format&fit=crop&w=140&q=80`} alt="" /><span>{product.name}<small>{formatPrice(product.price)}</small></span><span aria-hidden="true">→</span></button>) : <div className="dashboard-empty"><p>Keep the pieces you love close by saving a favorite.</p><button className="text-link text-button" onClick={() => onNavigate('/products')}>Browse the collection →</button></div>}
        </section>
      </div>
      <div className="dashboard-account"><span>{profile.email}</span><button className="text-link text-button" onClick={() => onNavigate('/profile')}>Update your details →</button></div>
      <p className="demo-note">Your account and order history are securely managed by the store.</p>
    </main>
  )
}

export default Dashboard
