import { useState } from 'react'
import Icon from '../components/icon.jsx'
import ProductCard from '../components/productcard.jsx'
import { imageUrl } from '../data/products.js'

function Home({ products, favorites, onAdd, onFavorite, onNavigate }) {
  const [subscribed, setSubscribed] = useState(false)

  function subscribe(event) {
    event.preventDefault()
    setSubscribed(true)
  }

  return (
    <main>
      <section className="hero">
        <div className="hero-copy">
          <span className="eyebrow"><span className="eyebrow-dot" /> GOOD THINGS, MADE THOUGHTFULLY</span>
          <h1>Make room<br />for <em>the good</em><br />stuff.</h1>
          <p>Everyday pieces, a little more considered. Made to be lived in, loved, and kept around.</p>
          <button className="primary-button" onClick={() => onNavigate('/products')}>Find your favorites <Icon name="right" size={17} /></button>
          <div className="hero-footnote"><span>01 — 08</span><span className="hero-line" /><span>THE EVERYDAY EDIT</span></div>
        </div>
        <div className="hero-visual">
          <img src={imageUrl('photo-1490481651871-ab68de25d43d', 1200)} alt="A curated selection of timeless wardrobe pieces" fetchPriority="high" />
          <div className="hero-sticker"><span>MADE TO</span><span>STAY AWHILE</span><span className="sticker-star">✳</span></div>
          <div className="hero-caption"><span>THE SLOWER THINGS COLLECTION</span><span>01 / 04</span></div>
        </div>
      </section>

      <section className="benefits" aria-label="Store benefits">
        <div><span className="benefit-number">01</span><p>Thoughtful materials</p></div>
        <div><span className="benefit-number">02</span><p>Made in small batches</p></div>
        <div><span className="benefit-number">03</span><p>Free shipping over $75</p></div>
        <span className="benefit-aside">GOOD FROM THE GET-GO</span>
      </section>

      <section className="shop-section" id="shop">
        <div className="section-heading">
          <div><span className="eyebrow">THINGS YOU’LL KEEP</span><h2>The everyday <span>edit.</span></h2></div>
          <button className="text-link text-button" onClick={() => onNavigate('/products')}>Shop everything <Icon name="right" size={16} /></button>
        </div>
        <div className="product-grid">
          {products.slice(0, 4).map((product) => (
            <ProductCard key={product.id} product={product} onAdd={onAdd} favorite={favorites.includes(product.id)} onFavorite={onFavorite} onSelect={(item) => onNavigate(`/products/${item.id}`)} />
          ))}
        </div>
        <div className="shop-more"><button onClick={() => onNavigate('/products')}>A little more to love <span>↗</span></button></div>
      </section>

      <section className="story-section" id="story">
        <div className="story-image">
          <img src={imageUrl('photo-1441986300917-64674bd600d8', 1000)} alt="A warm, sunlit independent shop" loading="lazy" />
          <span>LESS, BUT A LITTLE BETTER.</span>
        </div>
        <div className="story-copy">
          <span className="eyebrow">A NOTE FROM OUR LITTLE STUDIO</span>
          <h2>Good things<br />take <em>their time.</em></h2>
          <p>We believe the things you live with should feel like you. So we work with thoughtful makers, choose materials with care, and make fewer things that mean a little more.</p>
          <button className="text-link text-button" onClick={() => onNavigate('/products')}>Find your everyday pieces <Icon name="right" size={16} /></button>
          <span className="story-scribble">Made for real life, always.</span>
        </div>
      </section>

      <section className="newsletter" id="newsletter">
        <div><span className="eyebrow">A GOOD NOTE, NOW AND THEN</span><h2>A little more<br /><em>good in your inbox.</em></h2><p>New things, small joys, and a little something for your first order.</p></div>
        <form className="newsletter-form" onSubmit={subscribe}>
          {subscribed ? <p className="subscribed-message" role="status">Thanks for signing up. This demo doesn’t send emails.</p> : <><label htmlFor="newsletter-email">YOUR EMAIL ADDRESS</label><div className="email-field"><input id="newsletter-email" type="email" placeholder="you@somewhere.com" required /><button type="submit" aria-label="Subscribe to our newsletter"><Icon name="right" /></button></div><span>By subscribing, you agree to receive the occasional good note from us.</span></>}
        </form>
        <span className="newsletter-mark" aria-hidden="true">✳</span>
      </section>
    </main>
  )
}

export default Home