import { useState } from 'react'
import Icon from '../components/icon.jsx'

function Login({ onNavigate, onLogin, onResetPassword }) {
  const [mode, setMode] = useState('signin')
  const [showPassword, setShowPassword] = useState(false)
  const [status, setStatus] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function submit(event) {
    event.preventDefault()
    setStatus('')
    setSubmitting(true)
    const formData = new FormData(event.currentTarget)
    try {
      const email = String(formData.get('email') || '')
      if (mode === 'reset') {
        await onResetPassword(email)
        setStatus('If an account exists for that email, a password reset link is on its way.')
      } else {
        await onLogin({
          email,
          password: String(formData.get('password') || ''),
        })
      }
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Sign in failed. Please try again.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="account-page">
      <div className="account-visual">
        <img src="https://images.unsplash.com/photo-1490481651871-ab68de25d43d?auto=format&fit=crop&w=1200&q=85" alt="A thoughtfully styled everyday collection" />
        <div className="account-visual-note"><span className="eyebrow">A LITTLE MORE YOU</span><p>Good things<br />are better<br /><em>together.</em></p></div>
        <span className="account-visual-caption">YOUR EVERYDAY, A LITTLE MORE CONSIDERED.</span>
      </div>
      <section className="account-panel">
        <button className="account-back" onClick={() => onNavigate('/')}>← Back to the good stuff</button>
        <span className="eyebrow">{mode === 'reset' ? 'A FRESH START' : 'WELCOME BACK'}</span>
        <h1>{mode === 'reset' ? <>Forgot your<br /><em>password?</em></> : <>Good to<br />have you <em>back.</em></>}</h1>
        <p className="account-intro">{mode === 'reset' ? 'Enter your account email and we’ll send you a secure password reset link.' : 'Sign in to see your orders, save your favorites, and pick up where you left off.'}</p>
        <form className="account-form" onSubmit={submit}>
          <label>EMAIL ADDRESS<input type="email" name="email" autoComplete="email" placeholder="you@somewhere.com" required /></label>
          {mode === 'signin' && <label>PASSWORD<div className="password-field"><input type={showPassword ? 'text' : 'password'} name="password" autoComplete="current-password" placeholder="Your password" required /><button type="button" onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? 'Hide password' : 'Show password'}><Icon name={showPassword ? 'eyeOff' : 'eye'} size={18} /></button></div></label>}
          {mode === 'signin' && <button className="forgot-password" type="button" onClick={() => { setMode('reset'); setStatus('') }}>Forgot password?</button>}
          <button className="account-submit" type="submit" disabled={submitting}>{submitting ? 'One moment…' : mode === 'reset' ? 'Send reset link' : 'Sign in'} <Icon name="right" size={17} /></button>
          {status && <p className="account-status" role="alert">{status}</p>}
        </form>
        <div className="account-switch">{mode === 'reset' ? <>Remembered it? <button onClick={() => { setMode('signin'); setStatus('') }}>Back to sign in</button></> : <>New around here? <button onClick={() => onNavigate('/register')}>Create an account</button></>}</div>
        <p className="account-disclaimer">Your account is securely managed by Supabase.</p>
      </section>
    </main>
  )
}

export default Login
