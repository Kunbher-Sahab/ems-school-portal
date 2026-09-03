
# EMS Professional Full Website — Publish Ready

## Run locally
1. Install Node.js 18+.
2. Open this folder in Terminal/PowerShell.
3. Run:
   node server.js
4. Open: http://localhost:3000

No npm packages are required.

## Demo accounts
Student: student / demo123
Teacher: teacher / teacher123
Admin: admin / admin123
Principal: principal / principal123

## What is included
- Student + Teacher self-signup with their own password
- Teacher approval workflow
- Secure password hashing with Node crypto/scrypt
- Cookie session login/logout
- Role-aware dashboards
- Student results/attendance/progress
- Teacher/staff student record editing
- Notices
- AI Tutor demo endpoint
- Light / Dark / Automatic theme
- Animated intro, hover effects, reveal animations, premium login
- Supplied school photos and EMS logo

## Important
This is a real local full-stack prototype using a JSON database in /data/db.json. For internet production use, replace the JSON store with a hosted database, HTTPS, secure session storage, CSRF protection, rate limiting, email/password recovery and a production AI provider. Do not put real student data into a public deployment until those production controls are added.


## Publish online (Render)
1. Upload this project to a GitHub repository.
2. In Render, create a new Web Service from that repository.
3. Build command: leave empty.
4. Start command: `node server.js`.
5. After deployment, open the generated HTTPS URL.
6. Login with the demo account first to verify the deployment.

### Important for real school data
The included JSON database is suitable for a prototype/demo and hosts with persistent disk. Before using real student records at scale, move the data to a managed database and add production session storage, HTTPS-only cookies, CSRF protection, rate limiting, backups, password reset/email verification, audit logs and role-specific permissions.
