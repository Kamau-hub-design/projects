import Icon from './icon.jsx'
import { formatPrice, imageUrl } from '../data/products.js'

function ProductCard({ product, onAdd, favorite, onFavorite, onSelect }) {
  return (
    <article className="product-card">
      <div className="product-image-wrap">
        <button className="product-image-link" onClick={() => onSelect(product)} aria-label={`View ${product.name}`}>
          <img className="product-image" src={imageUrl(product.image)} alt={product.name} loading="lazy" />
        </button>
        {product.tag && <span className="product-tag">{product.tag}</span>}
        <button
          className={`favorite-button${favorite ? ' is-favorite' : ''}`}
          onClick={() => onFavorite(product.id)}
          aria-label={favorite ? `Remove ${product.name} from favorites` : `Add ${product.name} to favorites`}
          aria-pressed={favorite}
        >
          <Icon name="heart" size={18} />
        </button>
        <button className="quick-add" onClick={() => onAdd(product)}><Icon name="plus" size={16} /> Quick add</button>
      </div>
      <div className="product-info">
        <div>
          <h3><button className="product-title" onClick={() => onSelect(product)}>{product.name}</button></h3>
          <p>{product.color}</p>
        </div>
        <span className="product-price">{formatPrice(product.price)}</span>
      </div>
    </article>
  )
}

export default ProductCard