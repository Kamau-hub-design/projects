import { useEffect, useState } from 'react'

function Profile({ profile, favoriteCount, orderCount, onSave, onNavigate, onLogout }) {
  const [name, setName] = useState(profile.name)
  const [status, setStatus] = useState('')

  useEffect(() => {
    setName(profile.name)
  }, [profile])

  async function submit(event) {
    event.preventDefault()
    setStatus('')
    try {
      await onSave({ name: name.trim() })
      setStatus('Your profile was updated.')
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Your profile could not be updated.')
    }
  }

  return (
    <main className="shop-section profile-page">
      <div className="section-heading">
        <div><span className="eyebrow">YOUR STUDIO GOODS</span><h1 className="page-title">A little <span>about you.</span></h1></div>
      </div>
      <div className="profile-layout">
        <aside className="profile-sidebar">
          <div className="profile-avatar" aria-hidden="true">{(name || 'G').trim().charAt(0).toUpperCase()}</div>
          <h2>{name || 'Good friend'}</h2>
          <p>{profile.email || 'Your email goes here'}</p>
          <nav aria-label="Profile navigation">
            <button className="profile-nav-active">Your details</button>
            <button onClick={() => onNavigate('/orders')}>Order notes <span>{orderCount}</span></button>
            <button onClick={() => onNavigate('/products?filter=saved')}>Saved pieces <span>{favoriteCount}</span></button>
          </nav>
          <button className="profile-signout" onClick={onLogout}>Sign out</button>
        </aside>
        <section className="profile-content">
          <span className="eyebrow">YOUR DETAILS</span>
          <h2>Make yourself at home.</h2>
          <p>Update the name associated with your account. Your email stays linked to your sign-in.</p>
          <form className="profile-form" onSubmit={submit}>
            <label>YOUR NAME<input name="name" autoComplete="name" value={name} onChange={(event) => setName(event.target.value)} required /></label>
            <label>EMAIL ADDRESS<input type="email" name="email" autoComplete="email" value={profile.email} readOnly /></label>
            <button className="account-submit" type="submit">Save details</button>
            {status && <p className="account-status" role="status">{status}</p>}
          </form>
          <div className="profile-note"><strong>Your account details</strong><p>Your profile is managed securely by the store account service.</p></div>
        </section>
      </div>
    </main>
  )
}

export default Profile