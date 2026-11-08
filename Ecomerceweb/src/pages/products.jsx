import { useMemo, useState } from 'react'
import ProductCard from '../components/productcard.jsx'
import { categories } from '../data/products.js'

function Products({ products, favorites, onAdd, onFavorite, onNavigate, initialCategory = 'Everything', initialSearch = '', showFavorites = false }) {
  const [category, setCategory] = useState(initialCategory)
  const [search, setSearch] = useState(initialSearch)
  const visibleProducts = useMemo(() => products.filter((product) => {
    const matchesCategory = category === 'Everything' || product.category === category
    const matchesSearch = `${product.name} ${product.category} ${product.color}`.toLowerCase().includes(search.trim().toLowerCase())
    return matchesCategory && matchesSearch && (!showFavorites || favorites.includes(product.id))
  }), [category, favorites, products, search, showFavorites])

  return (
    <main className="shop-section products-page">
      <div className="section-heading">
        <div>
          <span className="eyebrow">{showFavorites ? 'YOUR LITTLE COLLECTION' : 'THINGS YOU’LL KEEP'}</span>
          <h1 className="page-title">{showFavorites ? <>Saved <span>for later.</span></> : <>The everyday <span>edit.</span></>}</h1>
        </div>
      </div>
      <div className="products-toolbar">
        <div className="category-tabs" role="group" aria-label="Filter products by category">
          {categories.map((item) => <button key={item} className={category === item ? 'selected' : ''} onClick={() => setCategory(item)} aria-pressed={category === item}>{item}</button>)}
        </div>
        <label className="products-search"><span className="visually-hidden">Search products</span><input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search the good stuff..." /></label>
        <span className="item-count">{visibleProducts.length} {visibleProducts.length === 1 ? 'piece' : 'pieces'}</span>
      </div>
      {visibleProducts.length ? (
        <div className="product-grid">
          {visibleProducts.map((product) => (
            <ProductCard key={product.id} product={product} onAdd={onAdd} favorite={favorites.includes(product.id)} onFavorite={onFavorite} onSelect={(item) => onNavigate(`/products/${item.id}`)} />
          ))}
        </div>
      ) : (
        <div className="empty-search">
          <p>{showFavorites && !favorites.length ? 'Your favorites will feel right at home here.' : 'Nothing here just yet.'}</p>
          <button onClick={() => { setSearch(''); setCategory('Everything'); if (showFavorites) onNavigate('/products') }}>Clear filters and browse all</button>
        </div>
      )}
    </main>
  )
}

export default Products