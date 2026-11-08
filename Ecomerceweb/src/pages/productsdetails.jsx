import { useState } from 'react'
import Icon from '../components/icon.jsx'
import { formatPrice, imageUrl } from '../data/products.js'

function ProductDetails({ product, favorite, onFavorite, onAdd, onNavigate }) {
  const [quantity, setQuantity] = useState(1)
  const [size, setSize] = useState('M')

  if (!product) {
    return (
      <main className="content-page empty-search">
        <p>We couldn’t find that piece.</p>
        <button onClick={() => onNavigate('/products')}>Browse the collection</button>
      </main>
    )
  }

  return (
    <main className="product-detail-page">
      <button className="back-link" onClick={() => onNavigate('/products')}>← Back to the collection</button>
      <div className="product-detail">
        <div className="detail-image-wrap"><img src={imageUrl(product.image, 1200)} alt={product.name} /></div>
        <section className="detail-copy">
          <span className="eyebrow">{product.category.toUpperCase()} · STUDIO GOODS</span>
          {product.tag && <span className="detail-tag">{product.tag}</span>}
          <h1>{product.name}</h1>
          <p className="detail-price">{formatPrice(product.price)}</p>
          <p className="detail-description">{product.description}</p>
          <p className="detail-color"><span>Color</span>{product.color}</p>
          {product.category === 'Clothing' && <label className="size-select">SIZE<select value={size} onChange={(event) => setSize(event.target.value)}><option>S</option><option>M</option><option>L</option></select></label>}
          <div className="detail-actions">
            <div className="quantity-control"><button onClick={() => setQuantity((value) => Math.max(1, value - 1))} aria-label="Decrease quantity"><Icon name="minus" size={14} /></button><span>{quantity}</span><button onClick={() => setQuantity((value) => value + 1)} aria-label="Increase quantity"><Icon name="plus" size={14} /></button></div>
            <button className="primary-button detail-add" onClick={() => onAdd(product, quantity, product.category === 'Clothing' ? `Size ${size}` : '')}>Add to bag <Icon name="right" size={16} /></button>
          </div>
          <button className={`detail-favorite${favorite ? ' is-favorite' : ''}`} onClick={() => onFavorite(product.id)} aria-pressed={favorite}><Icon name="heart" size={17} />{favorite ? 'Saved to your favorites' : 'Save for later'}</button>
          <div className="detail-note"><span>Thoughtful materials</span><span>Free shipping over $75</span><span>Made in small batches</span></div>
        </section>
      </div>
    </main>
  )
}

export default ProductDetails