import { useEffect, useState } from 'react'
import './App.css'
import AdminDashboard from './admin/dashboard.jsx'
import ManageOrders from './admin/manageorders.jsx'
import ManageProducts from './admin/manageproducts.jsx'
import Footer from './components/footer.jsx'
import Navbar from './components/navbar.jsx'
import { supabase } from './lib/supabase.js'
import Cart from './pages/cart.jsx'
import Checkout from './pages/checkout.jsx'
import Dashboard from './pages/dashboard.jsx'
import Home from './pages/home.jsx'
import Login from './pages/login.jsx'
import Orders from './pages/orders.jsx'
import PasswordReset from './pages/passwordreset.jsx'
import ProductDetails from './pages/productsdetails.jsx'
import Products from './pages/products.jsx'
import Profile from './pages/profile.jsx'
import Register from './pages/register.jsx'
import { categories, mapProductRecord, products } from './data/products.js'

const protectedRoutes = ['/dashboard', '/profile', '/orders', '/checkout']

function currentLocation() {
  return `${window.location.pathname}${window.location.search}${window.location.hash}`
}

function getInitialCart(catalog = products) {
  try {
    const saved = JSON.parse(window.sessionStorage.getItem('studio-goods-cart') || '[]')
    if (!Array.isArray(saved)) return []
    return saved.flatMap((item) => {
      const product = catalog.find((candidate) => candidate.id === Number(item.id))
      const quantity = Number(item.quantity)
      const validVariant = product?.category === 'Clothing'
        ? ['', 'Size S', 'Size M', 'Size L'].includes(item.variant || '')
        : !item.variant
      if (!product || !Number.isInteger(quantity) || quantity < 1 || quantity > 10 || !validVariant) return []
      const variant = item.variant || ''
      return [{ ...product, cartId: `${product.id}-${variant}`, quantity, variant }]
    })
  } catch {
    return []
  }
}

function App() {
  const [location, setLocation] = useState(currentLocation)
  const [cart, setCart] = useState(() => supabase ? [] : getInitialCart())
  const [cartReady, setCartReady] = useState(!supabase)
  const [catalogProducts, setCatalogProducts] = useState(supabase ? [] : products)
  const [favorites, setFavorites] = useState([])
  const [orders, setOrders] = useState([])
  const [customerNames, setCustomerNames] = useState({})
  const [user, setUser] = useState(null)
  const [profile, setProfile] = useState({ id: '', name: '', email: '', role: 'customer' })
  const [authReady, setAuthReady] = useState(false)
  const [dataError, setDataError] = useState('')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    function syncLocation() {
      setLocation(currentLocation())
    }
    window.addEventListener('popstate', syncLocation)
    return () => window.removeEventListener('popstate', syncLocation)
  }, [])

  useEffect(() => {
    if (!supabase) return undefined
    let active = true
    async function loadCatalog() {
      const { data, error } = await supabase.from('products')
        .select('id,name,category,price_cents,color,tag,image,description,is_active')
        .eq('is_active', true)
        .order('id')
      if (!active) return
      if (error) {
        setCatalogProducts([])
        setCart([])
        setCartReady(true)
        setDataError(`The product catalog could not be loaded: ${error.message}`)
        return
      }
      const catalog = (data || []).map(mapProductRecord)
      setCatalogProducts(catalog)
      setCart(getInitialCart(catalog))
      setCartReady(true)
    }
    loadCatalog().catch((error) => {
      if (!active) return
      setCatalogProducts([])
      setCart([])
      setCartReady(true)
      setDataError(error instanceof Error ? error.message : 'The product catalog could not be loaded.')
    })
    return () => { active = false }
  }, [])

  useEffect(() => {
    if (!supabase) {
      setAuthReady(true)
      return undefined
    }

    let active = true
    supabase.auth.getSession().then(({ data, error }) => {
      if (!active) return
      if (error) setDataError(`Could not restore your sign-in: ${error.message}`)
      setUser(data.session?.user ?? null)
      setAuthReady(true)
    }).catch((error) => {
      if (!active) return
      setDataError(error instanceof Error ? error.message : 'Could not restore your sign-in.')
      setAuthReady(true)
    })

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(session?.user ?? null)
      setAuthReady(true)
    })
    return () => {
      active = false
      subscription.unsubscribe()
    }
  }, [])

  useEffect(() => {
    if (!authReady || !user || !supabase) {
      setProfile({ id: '', name: '', email: '', role: 'customer' })
      setOrders([])
      setFavorites([])
      setCustomerNames({})
      return undefined
    }

    let active = true
    async function loadAccountData() {
      let ordersQuery = supabase.from('orders')
        .select('id,user_id,status,fulfillment_status,total_cents,currency,items,shipping_details,created_at')
        .order('created_at', { ascending: false })
      if (user.app_metadata?.role !== 'admin') {
        ordersQuery = ordersQuery.eq('user_id', user.id)
      }
      const [profileResult, ordersResult, favoritesResult, customersResult] = await Promise.all([
        supabase.from('profiles').select('full_name').eq('id', user.id).maybeSingle(),
        ordersQuery,
        supabase.from('favorites').select('product_id').eq('user_id', user.id),
        user.app_metadata?.role === 'admin'
          ? supabase.from('profiles').select('id,full_name')
          : Promise.resolve({ data: [], error: null }),
      ])
      if (!active) return

      const errors = [profileResult.error, ordersResult.error, favoritesResult.error, customersResult.error].filter(Boolean)
      setDataError(errors.length
        ? `Some account information could not be loaded: ${errors.map((error) => error.message).join('; ')}`
        : '')
      setProfile({
        id: user.id,
        name: profileResult.data?.full_name || user.user_metadata?.full_name || '',
        email: user.email || '',
        role: user.app_metadata?.role === 'admin' ? 'admin' : 'customer',
      })
      if (!ordersResult.error) {
        setOrders((ordersResult.data || []).map((order) => ({
          ...order,
          status: ({ pending: 'Payment pending', paid: 'Paid', cancelled: 'Cancelled', failed: 'Failed' })[order.status] || order.status,
          fulfillment_status: order.fulfillment_status || 'unfulfilled',
          items: Array.isArray(order.items) ? order.items : [],
          total: order.total_cents / 100,
          date: new Date(order.created_at).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' }),
        })))
      }
      if (!favoritesResult.error) setFavorites((favoritesResult.data || []).map((favorite) => favorite.product_id))
      if (!customersResult.error) {
        setCustomerNames(Object.fromEntries((customersResult.data || []).map((customer) => [customer.id, customer.full_name || 'Customer'])))
      }
    }

    loadAccountData().catch((error) => {
      if (active) setDataError(error instanceof Error ? error.message : 'Could not load your account data.')
    })
    return () => { active = false }
  }, [authReady, user])

  useEffect(() => {
    if (!notice) return undefined
    const timeout = window.setTimeout(() => setNotice(''), 3500)
    return () => window.clearTimeout(timeout)
  }, [notice])

  useEffect(() => {
    if (cartReady) {
      window.sessionStorage.setItem('studio-goods-cart', JSON.stringify(cart.map(({ id, quantity, variant }) => ({ id, quantity, variant }))))
    }
  }, [cart, cartReady])

  function navigate(path) {
    window.history.pushState({}, '', path)
    setLocation(currentLocation())
    if (path.includes('#')) {
      const target = path.split('#')[1]
      window.setTimeout(() => document.getElementById(target)?.scrollIntoView({ behavior: 'smooth' }), 0)
    } else {
      window.scrollTo({ top: 0, behavior: 'smooth' })
    }
  }

  function addToCart(product, quantity = 1, variant = '') {
    const cartId = `${product.id}-${variant}`
    setCart((items) => {
      const existing = items.find((item) => item.cartId === cartId)
      return existing
        ? items.map((item) => item.cartId === cartId ? { ...item, quantity: Math.min(10, item.quantity + quantity) } : item)
        : [...items, { ...product, cartId, quantity: Math.min(10, quantity), variant }]
    })
    setNotice(`${product.name} added to your bag`)
  }

  function updateQuantity(cartId, amount) {
    setCart((items) => items.map((item) => item.cartId === cartId ? { ...item, quantity: Math.min(10, item.quantity + amount) } : item).filter((item) => item.quantity > 0))
  }

  async function toggleFavorite(id) {
    if (!user || !supabase) {
      setNotice('Sign in to save your favorite pieces.')
      return
    }
    const wasSaved = favorites.includes(id)
    setFavorites((items) => wasSaved ? items.filter((item) => item !== id) : [...items, id])
    try {
      const result = wasSaved
        ? await supabase.from('favorites').delete().eq('user_id', user.id).eq('product_id', id)
        : await supabase.from('favorites').insert({ user_id: user.id, product_id: id })
      if (result.error) throw result.error
    } catch (error) {
      setFavorites((items) => wasSaved ? [...items, id] : items.filter((item) => item !== id))
      setNotice(`Could not update your saved pieces: ${error.message || 'Please try again.'}`)
    }
  }

  async function registerAccount(details) {
    if (!supabase) throw new Error('Account services are not configured. Please try again later.')
    const { data, error } = await supabase.auth.signUp({
      email: details.email.trim(),
      password: details.password,
      options: {
        data: { full_name: details.name.trim() },
        emailRedirectTo: `${window.location.origin}/dashboard`,
      },
    })
    if (error) throw error
    if (!data.session) return { emailConfirmationRequired: true }
    setUser(data.session.user)
    navigate(data.session.user.app_metadata?.role === 'admin' ? '/admin' : '/dashboard')
    return { emailConfirmationRequired: false }
  }

  async function signIn(credentials) {
    if (!supabase) throw new Error('Account services are not configured. Please try again later.')
    const { data, error } = await supabase.auth.signInWithPassword(credentials)
    if (error) throw error
    setUser(data.user)
    const returnTo = new URLSearchParams(window.location.search).get('returnTo')
    navigate(returnTo?.startsWith('/') && !returnTo.startsWith('//')
      ? returnTo
      : data.user.app_metadata?.role === 'admin' ? '/admin' : '/dashboard')
  }

  async function requestPasswordReset(email) {
    if (!supabase) throw new Error('Account services are not configured. Please try again later.')
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/reset-password`,
    })
    if (error) throw error
  }

  async function updatePassword(password) {
    if (!supabase) throw new Error('Account services are not configured. Please try again later.')
    const { error } = await supabase.auth.updateUser({ password })
    if (error) throw error
  }

  async function saveProfile(details) {
    if (!supabase || !user) throw new Error('Please sign in again to update your profile.')
    const { data, error } = await supabase.from('profiles')
      .update({ full_name: details.name.trim() })
      .eq('id', user.id)
      .select('full_name')
      .single()
    if (error) throw error
    setProfile((current) => ({ ...current, name: data.full_name }))
  }

  async function saveProduct(product) {
    if (!supabase || user?.app_metadata?.role !== 'admin') {
      throw new Error('You do not have permission to manage products.')
    }
    const record = {
      name: product.name.trim(),
      category: product.category,
      price_cents: Math.round(Number(product.price) * 100),
      color: product.color.trim(),
      tag: product.tag.trim(),
      image: product.image.trim(),
      description: product.description.trim(),
      is_active: product.isActive !== false,
    }
    const query = product.id
      ? supabase.from('products').update(record).eq('id', product.id)
      : supabase.from('products').insert(record)
    const { data, error } = await query
      .select('id,name,category,price_cents,color,tag,image,description,is_active')
      .single()
    if (error) throw new Error(`Could not save product: ${error.message}`)
    const updatedProduct = mapProductRecord(data)
    setCatalogProducts((current) => updatedProduct.isActive
      ? [...current.filter((item) => item.id !== updatedProduct.id), updatedProduct].sort((a, b) => a.id - b.id)
      : current.filter((item) => item.id !== updatedProduct.id))
    if (updatedProduct.isActive) {
      setCart((current) => current.map((item) => item.id === updatedProduct.id
        ? { ...item, ...updatedProduct, cartId: `${updatedProduct.id}-${item.variant}` }
        : item))
    } else {
      setCart((current) => current.filter((item) => item.id !== updatedProduct.id))
    }
    return updatedProduct
  }

  async function setProductActive(id, isActive) {
    if (!supabase || user?.app_metadata?.role !== 'admin') {
      throw new Error('You do not have permission to manage products.')
    }
    const { data, error } = await supabase.from('products')
      .update({ is_active: isActive })
      .eq('id', id)
      .select('id,name,category,price_cents,color,tag,image,description,is_active')
      .single()
    if (error) throw new Error(`Could not update product status: ${error.message}`)
    const updatedProduct = mapProductRecord(data)
    setCatalogProducts((current) => isActive
      ? [...current.filter((item) => item.id !== id), updatedProduct].sort((a, b) => a.id - b.id)
      : current.filter((item) => item.id !== id))
    if (!isActive) setCart((current) => current.filter((item) => item.id !== id))
    else {
      setCart((current) => current.map((item) => item.id === id
        ? { ...item, ...updatedProduct, cartId: `${id}-${item.variant}` }
        : item))
    }
    return updatedProduct
  }

  async function changeFulfillment(orderId, fulfillmentStatus) {
    if (!supabase || user?.app_metadata?.role !== 'admin') {
      throw new Error('You do not have permission to manage order fulfillment.')
    }
    const allowedStatuses = ['unfulfilled', 'processing', 'shipped', 'delivered', 'returned']
    if (!allowedStatuses.includes(fulfillmentStatus)) throw new Error('Choose a valid fulfillment status.')
    const { error } = await supabase.from('orders')
      .update({ fulfillment_status: fulfillmentStatus })
      .eq('id', orderId)
      .eq('status', 'paid')
      .select('id')
      .single()
    if (error) throw new Error(`Could not update order fulfillment: ${error.message}`)
    setOrders((current) => current.map((order) => order.id === orderId
      ? { ...order, fulfillment_status: fulfillmentStatus }
      : order))
  }

  async function signOut() {
    if (!supabase) return
    const { error } = await supabase.auth.signOut()
    if (error) {
      setDataError(`Could not sign out: ${error.message}`)
      return
    }
    setUser(null)
    navigate('/login')
  }

  async function startCheckout() {
    if (!supabase || !user) throw new Error('Sign in before starting checkout.')
    const { data: { session }, error: sessionError } = await supabase.auth.getSession()
    if (sessionError) throw sessionError
    if (!session?.access_token) throw new Error('Your sign-in has expired. Please sign in again.')
    const response = await fetch('/api/create-checkout-session', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ items: cart.map(({ id, quantity, variant }) => ({ id, quantity, variant })) }),
    })
    let result
    try {
      result = await response.json()
    } catch {
      throw new Error('Checkout returned an invalid response. Please try again.')
    }
    if (!response.ok) throw new Error(result.error || 'Checkout could not be started.')
    const checkoutUrl = new URL(result.url)
    if (checkoutUrl.protocol !== 'https:' || !checkoutUrl.hostname.endsWith('stripe.com')) {
      throw new Error('The checkout provider returned an invalid URL.')
    }
    window.location.assign(checkoutUrl.href)
  }

  const url = new URL(location, 'http://studio-goods.local')
  const routePath = url.pathname
  const routeParams = url.searchParams
  const cartCount = cart.reduce((total, item) => total + item.quantity, 0)
  const favoriteProducts = favorites.length
  const categoryParam = categories.includes(routeParams.get('category')) ? routeParams.get('category') : 'Everything'
  const searchParam = routeParams.get('search') || ''
  const showFavorites = routeParams.get('filter') === 'saved'
  const productMatch = routePath.match(/^\/products\/(\d+)\/?$/)
  const selectedProduct = productMatch ? catalogProducts.find((product) => product.id === Number(productMatch[1])) : null
  const isAdminRoute = /^\/admin(?:\/|$)/.test(routePath)
  useEffect(() => {
    if (!authReady || (!protectedRoutes.includes(routePath) && !isAdminRoute) || user) return
    navigate(`/login?returnTo=${encodeURIComponent(routePath)}`)
  }, [authReady, routePath, user, isAdminRoute])

  let page
  if (!supabase && (['/login', '/register', '/reset-password', ...protectedRoutes].includes(routePath) || isAdminRoute)) {
    page = <main className="content-page service-unavailable"><span className="eyebrow">ACCOUNT AND CHECKOUT SERVICES</span><h1>One last setup step.</h1><p>Add your Supabase project URL and publishable key as environment variables to enable secure accounts, saved pieces, order history, and checkout.</p></main>
  } else if ((protectedRoutes.includes(routePath) || isAdminRoute) && !authReady) {
    page = <main className="content-page auth-loading" role="status">Checking your sign-in…</main>
  } else if (routePath === '/') {
    page = <Home products={catalogProducts} favorites={favorites} onAdd={addToCart} onFavorite={toggleFavorite} onNavigate={navigate} />
  } else if (routePath === '/products' || routePath === '/products/') {
    page = <Products key={location} products={catalogProducts} favorites={favorites} onAdd={addToCart} onFavorite={toggleFavorite} onNavigate={navigate} initialCategory={categoryParam} initialSearch={searchParam} showFavorites={showFavorites} />
  } else if (productMatch) {
    page = <ProductDetails product={selectedProduct} favorite={selectedProduct ? favorites.includes(selectedProduct.id) : false} onFavorite={toggleFavorite} onAdd={addToCart} onNavigate={navigate} />
  } else if (routePath === '/cart') {
    page = <Cart cart={cart} onUpdateQuantity={updateQuantity} onNavigate={navigate} />
  } else if (routePath === '/checkout') {
    page = <Checkout cart={cart} profile={profile} onNavigate={navigate} onCheckout={startCheckout} />
  } else if (routePath === '/login' || routePath === '/login/') {
    page = <Login onNavigate={navigate} onLogin={signIn} onResetPassword={requestPasswordReset} />
  } else if (routePath === '/register' || routePath === '/register/') {
    page = <Register onNavigate={navigate} onRegister={registerAccount} />
  } else if (routePath === '/reset-password' || routePath === '/reset-password/') {
    page = <PasswordReset onNavigate={navigate} onUpdatePassword={updatePassword} />
  } else if (routePath === '/dashboard' || routePath === '/dashboard/') {
    page = <Dashboard profile={profile} orders={orders} favorites={favorites} products={catalogProducts} cartCount={cartCount} onNavigate={navigate} onLogout={signOut} />
  } else if (isAdminRoute && user?.app_metadata?.role !== 'admin') {
    page = <main className="content-page"><span className="eyebrow">ADMIN ACCESS</span><h1>Not authorized.</h1><p>This account does not have permission to access the store admin area.</p><button className="text-link text-button" onClick={() => navigate(user ? '/dashboard' : '/login')}>Return to your account →</button></main>
  } else if (routePath === '/admin' || routePath === '/admin/') {
    page = <AdminDashboard orders={orders} customers={customerNames} productCount={catalogProducts.length} onNavigate={navigate} onLogout={signOut} />
  } else if (routePath === '/admin/orders' || routePath === '/admin/orders/') {
    page = <ManageOrders orders={orders} customers={customerNames} onFulfillmentChange={changeFulfillment} onNavigate={navigate} />
  } else if (routePath === '/admin/products' || routePath === '/admin/products/') {
    page = <ManageProducts supabase={supabase} onSaveProduct={saveProduct} onSetProductActive={setProductActive} onNavigate={navigate} />
  } else if (routePath === '/profile' || routePath === '/profile/') {
    page = <Profile profile={profile} favoriteCount={favoriteProducts} orderCount={orders.length} onSave={saveProfile} onNavigate={navigate} onLogout={signOut} />
  } else if (routePath === '/orders' || routePath === '/orders/') {
    page = <Orders orders={orders} onNavigate={navigate} paymentSuccess={routeParams.get('checkout') === 'success'} />
  } else {
    page = <main className="content-page empty-search"><p>That page isn’t here, but the good stuff is.</p><button onClick={() => navigate('/')}>Back to the shop</button></main>
  }

  return (
    <div className="store">
      <Navbar cartCount={cartCount} favoriteCount={favoriteProducts} profile={profile} onNavigate={navigate} />
      {page}
      <Footer onNavigate={navigate} />
      {dataError && <div className="toast service-toast" role="alert">{dataError}</div>}
      {notice && <div className="toast" role="status" aria-live="polite"><span>{notice}</span><button onClick={() => { setNotice(''); navigate('/cart') }}>View bag</button></div>}
    </div>
  )
}

export default App
