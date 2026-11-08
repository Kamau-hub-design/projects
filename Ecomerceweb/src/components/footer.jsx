function Footer({ onNavigate }) {
  return (
    <footer className="site-footer">
      <a className="wordmark footer-wordmark" href="/" onClick={(event) => { event.preventDefault(); onNavigate('/') }}>studio<span>goods</span><i>.</i></a>
      <nav className="footer-links" aria-label="Footer navigation">
        <a href="/products" onClick={(event) => { event.preventDefault(); onNavigate('/products') }}>Shop</a>
        <a href="/orders" onClick={(event) => { event.preventDefault(); onNavigate('/orders') }}>Orders</a>
        <a href="/profile" onClick={(event) => { event.preventDefault(); onNavigate('/profile') }}>Profile</a>
        <a href="/login" onClick={(event) => { event.preventDefault(); onNavigate('/login') }}>Sign in</a>
      </nav>
      <span>THOUGHTFULLY MADE, EVERY DAY.</span>
      <span>© {new Date().getFullYear()} STUDIO GOODS</span>
    </footer>
  )
}

export default Footer