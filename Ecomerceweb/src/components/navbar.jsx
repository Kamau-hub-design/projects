import { useState } from 'react'
import Icon from './icon.jsx'

function Navbar({ cartCount, favoriteCount, profile, onNavigate }) {
  const [searchOpen, setSearchOpen] = useState(false)
  const [search, setSearch] = useState('')
  const accountPath = profile.email ? profile.role === 'admin' ? '/admin' : '/dashboard' : '/login'
  const accountLabel = profile.email ? profile.role === 'admin' ? 'Admin' : 'My account' : 'Sign in'

  function navigate(event, path) {
    event.preventDefault()
    setSearchOpen(false)
    onNavigate(path)
  }

  function submitSearch(event) {
    event.preventDefault()
    setSearchOpen(false)
    onNavigate(`/products?search=${encodeURIComponent(search.trim())}`)
  }

  return (
    <>
      <div className="announcement">A little something extra: free shipping on orders over $75</div>
      <header className="site-header">
        <a className="wordmark" href="/" onClick={(event) => navigate(event, '/')}>studio<span>goods</span><i>.</i></a>
        <nav className="main-nav" aria-label="Main navigation">
          <a href="/products" onClick={(event) => navigate(event, '/products')}>Shop all</a>
          <a href="/products?category=Clothing" onClick={(event) => navigate(event, '/products?category=Clothing')}>Clothing</a>
          <a href="/products?category=Bags" onClick={(event) => navigate(event, '/products?category=Bags')}>Bags</a>
          <a href="/products?category=Home" onClick={(event) => navigate(event, '/products?category=Home')}>Home & living</a>
          <a href="/#story" onClick={(event) => navigate(event, '/#story')}>Our story</a>
        </nav>
        <div className="header-actions">
          <button className={`icon-button search-trigger${searchOpen ? ' active' : ''}`} onClick={() => setSearchOpen(!searchOpen)} aria-label="Search products" aria-expanded={searchOpen}><Icon name="search" /></button>
          <a className="icon-button favorite-trigger" href="/products?filter=saved" onClick={(event) => navigate(event, '/products?filter=saved')} aria-label={`Saved products, ${favoriteCount} saved`}><Icon name="heart" /><span>Saved ({favoriteCount})</span></a>
          <a className="icon-button account-trigger" href={accountPath} onClick={(event) => navigate(event, accountPath)} aria-label={profile.email ? `Open ${accountLabel.toLowerCase()}` : 'Sign in to your account'}><Icon name="user" /><span>{accountLabel}</span></a>
          <a className="icon-button bag-trigger" href="/cart" onClick={(event) => navigate(event, '/cart')} aria-label={`Open shopping bag, ${cartCount} items`}><Icon name="bag" /><span>Bag ({cartCount})</span></a>
        </div>
      </header>
      {searchOpen && (
        <form className="search-bar" role="search" onSubmit={submitSearch}>
          <Icon name="search" />
          <input autoFocus value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search the good stuff..." aria-label="Search products" />
          {search && <button type="button" onClick={() => setSearch('')} aria-label="Clear search"><Icon name="close" /></button>}
          <button type="button" onClick={() => setSearchOpen(false)} aria-label="Close search"><Icon name="close" /></button>
        </form>
      )}
    </>
  )
}

export default Navbar