import { useState } from 'react'
import Icon from '../components/icon.jsx'

function Register({ onNavigate, onRegister }) {
  const [showPassword, setShowPassword] = useState(false)
  const [status, setStatus] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function submit(event) {
    event.preventDefault()
    const formData = new FormData(event.currentTarget)
    const name = String(formData.get('name') || '').trim()
    const email = String(formData.get('email') || '').trim()
    const password = String(formData.get('password') || '')
    const confirmPassword = String(formData.get('confirmPassword') || '')
    setStatus('')

    if (password !== confirmPassword) {
      setStatus('Those passwords don’t match. Please check and try again.')
      return
    }

    setSubmitting(true)
    try {
      const result = await onRegister({ name, email, password })
      if (result?.emailConfirmationRequired) {
        setStatus('Check your email and confirm your account before signing in.')
      }
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Registration failed. Please try again.')
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
        <span className="eyebrow">MAKE YOURSELF AT HOME</span>
        <h1>Join the<br /><em>good list.</em></h1>
        <p className="account-intro">Create your demo profile to keep your order notes and favorites together in this session.</p>
        <form className="account-form" onSubmit={submit}>
          <label>YOUR NAME<input name="name" autoComplete="name" placeholder="How should we call you?" required /></label>
          <label>EMAIL ADDRESS<input type="email" name="email" autoComplete="email" placeholder="you@somewhere.com" required /></label>
          <label>PASSWORD<div className="password-field"><input type={showPassword ? 'text' : 'password'} name="password" autoComplete="new-password" placeholder="At least 8 characters" minLength={8} required /><button type="button" onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? 'Hide password' : 'Show password'}><Icon name={showPassword ? 'eyeOff' : 'eye'} size={18} /></button></div></label>
          <label>CONFIRM PASSWORD<input type="password" name="confirmPassword" autoComplete="new-password" placeholder="Enter your password again" minLength={8} required /></label>
          <button className="account-submit" type="submit" disabled={submitting}>{submitting ? 'Creating account…' : 'Create account'} <Icon name="right" size={17} /></button>
          {status && <p className="account-status" role="alert">{status}</p>}
        </form>
        <div className="account-switch">Already part of the good list? <button onClick={() => onNavigate('/login')}>Sign in instead</button></div>
        <p className="account-disclaimer">Demo only — password verification is local to this browser, not a secure production account system.</p>
      </section>
    </main>
  )
}

export default Register