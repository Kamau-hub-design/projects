import { useState } from 'react'
import Icon from '../components/icon.jsx'

function PasswordReset({ onNavigate, onUpdatePassword }) {
  const [showPassword, setShowPassword] = useState(false)
  const [status, setStatus] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function submit(event) {
    event.preventDefault()
    const formData = new FormData(event.currentTarget)
    const password = String(formData.get('password') || '')
    if (password !== formData.get('confirmPassword')) {
      setStatus('Those passwords don’t match. Please check and try again.')
      return
    }

    setStatus('')
    setSubmitting(true)
    try {
      await onUpdatePassword(password)
      navigateToDashboard()
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Your password could not be updated.')
    } finally {
      setSubmitting(false)
    }
  }

  function navigateToDashboard() {
    onNavigate('/dashboard')
  }

  return (
    <main className="account-page">
      <div className="account-visual">
        <img src="https://images.unsplash.com/photo-1490481651871-ab68de25d43d?auto=format&fit=crop&w=1200&q=85" alt="A thoughtfully styled everyday collection" />
        <div className="account-visual-note"><span className="eyebrow">A LITTLE MORE YOU</span><p>Good things<br />are better<br /><em>together.</em></p></div>
        <span className="account-visual-caption">YOUR EVERYDAY, A LITTLE MORE CONSIDERED.</span>
      </div>
      <section className="account-panel">
        <button className="account-back" onClick={() => onNavigate('/login')}>← Back to sign in</button>
        <span className="eyebrow">A FRESH START</span>
        <h1>Choose a<br /><em>new password.</em></h1>
        <p className="account-intro">Set a new password for your account. Use at least 8 characters.</p>
        <form className="account-form" onSubmit={submit}>
          <label>NEW PASSWORD<div className="password-field"><input type={showPassword ? 'text' : 'password'} name="password" autoComplete="new-password" minLength={8} required /><button type="button" onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? 'Hide password' : 'Show password'}><Icon name={showPassword ? 'eyeOff' : 'eye'} size={18} /></button></div></label>
          <label>CONFIRM NEW PASSWORD<input type="password" name="confirmPassword" autoComplete="new-password" minLength={8} required /></label>
          <button className="account-submit" type="submit" disabled={submitting}>{submitting ? 'Updating password…' : 'Update password'} <Icon name="right" size={17} /></button>
          {status && <p className="account-status" role="alert">{status}</p>}
        </form>
        <p className="account-disclaimer">Your account is securely managed by Supabase.</p>
      </section>
    </main>
  )
}

export default PasswordReset
