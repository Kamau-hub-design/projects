import { useEffect, useState } from 'react'
import { categories, formatPrice, imageUrl } from '../data/products.js'

const blankProduct = {
  name: '',
  category: 'Home',
  price: '',
  color: '',
  tag: '',
  image: '',
  description: '',
  isActive: true,
}

function ManageProducts({ supabase, onSaveProduct, onSetProductActive, onNavigate }) {
  const [products, setProducts] = useState([])
  const [form, setForm] = useState(blankProduct)
  const [editingId, setEditingId] = useState(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    async function loadProducts() {
      const { data, error: loadError } = await supabase.from('products')
        .select('id,name,category,price_cents,color,tag,image,description,is_active')
        .order('id')
      if (!active) return
      if (loadError) setError(`Products could not be loaded: ${loadError.message}`)
      else setProducts(data.map((product) => ({
        ...product,
        price: product.price_cents / 100,
        isActive: product.is_active,
      })))
      setLoading(false)
    }
    loadProducts().catch((loadError) => {
      if (active) {
        setError(loadError instanceof Error ? loadError.message : 'Products could not be loaded.')
        setLoading(false)
      }
    })
    return () => { active = false }
  }, [supabase])

  function startEditing(product) {
    setEditingId(product.id)
    setForm({
      name: product.name,
      category: product.category,
      price: String(product.price),
      color: product.color,
      tag: product.tag,
      image: product.image,
      description: product.description,
      isActive: product.isActive,
    })
    setMessage('')
    setError('')
  }

  function resetForm() {
    setEditingId(null)
    setForm(blankProduct)
  }

  async function submit(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    setMessage('')
    try {
      const product = await onSaveProduct({ ...form, price: Number(form.price), id: editingId })
      setProducts((current) => {
        const existing = current.some((item) => item.id === product.id)
        return (existing
          ? current.map((item) => item.id === product.id ? product : item)
          : [...current, product]).sort((a, b) => a.id - b.id)
      })
      setMessage(editingId ? 'Product changes saved.' : 'Product added to the catalog.')
      resetForm()
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : 'Product could not be saved.')
    } finally {
      setBusy(false)
    }
  }

  async function toggleActive(product) {
    setBusy(true)
    setError('')
    setMessage('')
    try {
      const updated = await onSetProductActive(product.id, !product.isActive)
      setProducts((current) => current.map((item) => item.id === updated.id ? updated : item))
      setMessage(updated.isActive ? 'Product restored to the storefront.' : 'Product archived from the storefront.')
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : 'Product status could not be updated.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="shop-section admin-dashboard">
      <button className="back-link" onClick={() => onNavigate('/admin')}>← Admin overview</button>
      <div className="dashboard-welcome admin-page-heading">
        <div><span className="eyebrow">STUDIO GOODS · ADMIN</span><h1>Manage <em>products.</em></h1><p>Add new pieces, edit details, or archive products from the storefront.</p></div>
      </div>
      <div className="admin-products-layout">
        <section className="dashboard-panel admin-product-form-panel">
          <div className="dashboard-panel-heading"><div><span className="eyebrow">{editingId ? 'EDIT CATALOG' : 'NEW CATALOG ENTRY'}</span><h2>{editingId ? 'Update a piece' : 'Add a piece'}</h2></div></div>
          <form className="admin-product-form" onSubmit={submit}>
            <label>PRODUCT NAME<input value={form.name} maxLength="120" required onChange={(event) => setForm({ ...form, name: event.target.value })} /></label>
            <div className="checkout-field-row">
              <label>CATEGORY<select value={form.category} onChange={(event) => setForm({ ...form, category: event.target.value })}>{categories.filter((category) => category !== 'Everything').map((category) => <option key={category}>{category}</option>)}</select></label>
              <label>PRICE (USD)<input type="number" min="0.01" max="100000" step="0.01" required value={form.price} onChange={(event) => setForm({ ...form, price: event.target.value })} /></label>
            </div>
            <label>COLOR OR VARIANT<input value={form.color} maxLength="120" onChange={(event) => setForm({ ...form, color: event.target.value })} /></label>
            <label>TAG<input value={form.tag} maxLength="60" placeholder="Optional" onChange={(event) => setForm({ ...form, tag: event.target.value })} /></label>
            <label>UNSPLASH IMAGE ID<input value={form.image} placeholder="photo-..." pattern="photo-[a-zA-Z0-9-]+" title="Use a photo ID such as photo-1544816155-12df9643f363" required onChange={(event) => setForm({ ...form, image: event.target.value })} /></label>
            <label>DESCRIPTION<textarea value={form.description} maxLength="1000" rows="4" required onChange={(event) => setForm({ ...form, description: event.target.value })} /></label>
            <div className="admin-form-actions"><button className="account-submit" type="submit" disabled={busy}>{busy ? 'Saving…' : editingId ? 'Save changes' : 'Add product'}</button>{editingId && <button className="dashboard-signout" type="button" onClick={resetForm}>Cancel edit</button>}</div>
          </form>
          {message && <p className="admin-feedback" role="status">{message}</p>}
          {error && <p className="account-status" role="alert">{error}</p>}
        </section>

        <section className="dashboard-panel admin-products-list-panel">
          <div className="dashboard-panel-heading"><div><span className="eyebrow">CATALOG</span><h2>All products</h2></div><span className="item-count">{products.length}</span></div>
          {loading ? <p className="dashboard-empty" role="status">Loading products…</p> : error && !products.length ? <p className="dashboard-empty">Could not load catalog records.</p> : products.map((product) => (
            <article className={`admin-product-row${product.isActive ? '' : ' is-archived'}`} key={product.id}>
              <img src={imageUrl(product.image, 140)} alt="" />
              <div className="admin-product-copy"><strong>{product.name}</strong><span>{product.category} · {formatPrice(product.price)}</span><small>{product.isActive ? 'On storefront' : 'Archived'}</small></div>
              <div className="admin-product-actions"><button className="text-link text-button" onClick={() => startEditing(product)}>Edit</button><button className="text-link text-button" disabled={busy} onClick={() => toggleActive(product)}>{product.isActive ? 'Archive' : 'Restore'}</button></div>
            </article>
          ))}
        </section>
      </div>
    </main>
  )
}

export default ManageProducts