import Icon from '../components/icon.jsx'
import { formatPrice, imageUrl } from '../data/products.js'

function Cart({ cart, onUpdateQuantity, onNavigate }) {
  const subtotal = cart.reduce((total, item) => total + item.price * item.quantity, 0)
  const shippingRemaining = Math.max(0, 75 - subtotal)
  const shippingProgress = Math.min(100, (subtotal / 75) * 100)

  return (
    <main className="shop-section cart-page">
      <div className="section-heading">
        <div><span className="eyebrow">A FEW GOOD THINGS</span><h1 className="page-title">Your <span>bag.</span></h1></div>
        <span className="item-count">{cart.reduce((total, item) => total + item.quantity, 0)} items</span>
      </div>
      {!cart.length ? (
        <div className="empty-cart-page">
          <span className="empty-bag-icon"><Icon name="bag" size={26} /></span>
          <h2>Your bag is taking a little break.</h2>
          <p>Find something lovely to bring home.</p>
          <button className="primary-button" onClick={() => onNavigate('/products')}>Go find the good stuff <Icon name="right" size={16} /></button>
        </div>
      ) : (
        <div className="cart-layout">
          <section className="cart-list" aria-label="Items in your bag">
            <div className="shipping-note">{shippingRemaining ? <>You’re {formatPrice(shippingRemaining)} away from free shipping.</> : 'Lovely — your order ships free.'}<div className="shipping-progress"><span style={{ width: `${shippingProgress}%` }} /></div></div>
            {cart.map((item) => (
              <article className="cart-item cart-page-item" key={item.cartId}>
                <button className="cart-image-button" onClick={() => onNavigate(`/products/${item.id}`)} aria-label={`View ${item.name}`}><img src={imageUrl(item.image, 220)} alt={item.name} /></button>
                <div className="cart-item-info">
                  <h2><button className="product-title" onClick={() => onNavigate(`/products/${item.id}`)}>{item.name}</button></h2>
                  <p>{item.color}{item.variant ? ` · ${item.variant}` : ''}</p>
                  <div className="quantity-control">
                    <button onClick={() => onUpdateQuantity(item.cartId, -1)} aria-label={`Remove one ${item.name}`}><Icon name="minus" size={13} /></button>
                    <span>{item.quantity}</span>
                    <button onClick={() => onUpdateQuantity(item.cartId, 1)} aria-label={`Add one ${item.name}`}><Icon name="plus" size={13} /></button>
                  </div>
                  <button className="remove-item" onClick={() => onUpdateQuantity(item.cartId, -item.quantity)}>Remove</button>
                </div>
                <span className="cart-item-price">{formatPrice(item.price * item.quantity)}</span>
              </article>
            ))}
            <button className="continue-shopping" onClick={() => onNavigate('/products')}>Continue shopping</button>
          </section>
          <aside className="cart-summary cart-page-summary">
            <h2>Order summary</h2>
            <div><span>Subtotal</span><span>{formatPrice(subtotal)}</span></div>
            <div><span>Shipping</span><span>{shippingRemaining ? 'Calculated at checkout' : 'Free'}</span></div>
            <p>Taxes and shipping are calculated at checkout.</p>
            <button className="checkout-button" onClick={() => onNavigate('/checkout')}>Continue to checkout <Icon name="right" size={16} /></button>
            <p className="demo-note">Secure checkout demo — no payment is processed.</p>
          </aside>
        </div>
      )}
    </main>
  )
}

export default Cart