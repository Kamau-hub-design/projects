# Gifted Jannod Enterprise E-commerce Platform

A full-featured e-commerce platform with a Node.js backend and responsive frontend, supporting multi-regional payments and admin management.

## Features

- Responsive single-page application
- Multi-region support with localized payment methods
- Admin dashboard for order management
- Real-time order tracking
- Two-factor authentication
- Secure payment processing simulation
- Black Friday countdown and seasonal promotions
- Product categories and search
- Customer reviews system
- SQLite database for persistence

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
npm start
```

3. Open `index.html/combined-shop.html` in your browser

## Environment Variables

Create a `.env` file with these variables:
```
ADMIN_ACCESS_CODE=your_admin_code
RECAPTCHA_SECRET=your_recaptcha_secret
RECAPTCHA_SITE_KEY=your_recaptcha_site_key
DB_FILE=data.db
DEV_SHOW_OTP=true  # Set to false in production
```

## Tech Stack

- Frontend: Vanilla JavaScript, HTML5, CSS3
- Backend: Node.js, Express
- Database: SQLite
- Security: bcrypt, helmet, express-rate-limit
- APIs: exchangerate.host for currency conversion

## Security Features

- Password hashing with bcrypt
- Rate limiting
- Helmet security headers
- reCAPTCHA verification
- Admin-approved two-factor authentication
- IP-based firewall

## License

MIT License - See LICENSE file for details