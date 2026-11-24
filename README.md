# link

Code that powers retrac.link 🔗 — a small link shortener running on Cloudflare Workers with a D1 database.

## Features

- **Dashboard** at `retrac.link/dashboard`, protected by the `DASHBOARD_PASSWORD` secret
- **Create links** with a custom short code (`retrac.link/yt`) or a random one
- **Nicknames** so you can tell your links apart
- **Aliases**: extra short codes for the same link (`retrac.link/github` and `retrac.link/gh`). Clicks on any alias count toward the main link.
- **Password-protected links**: visitors have to enter a password before they're redirected (passwords are stored hashed with PBKDF2)
- **Edit** a link's destination, short code, nickname, password, or expiry
- **Disable**, **expire**, or **delete** links
- **Click counts** for every link
- **Master link**: choose where `retrac.link` itself sends visitors

## Deploy

1. Install dependencies:

   ```sh
   npm install
   ```

2. Create the D1 database and paste the `database_id` it prints into `wrangler.toml`:

   ```sh
   npx wrangler d1 create retrac-link
   ```

   You don't need to run any migrations. The tables are created automatically on the first request.

3. Deploy:

   ```sh
   npm run deploy
   ```

   `wrangler.toml` attaches the Worker to `retrac.link` as a custom domain. This requires `retrac.link` to be a zone on your Cloudflare account.

4. Set the dashboard password. In the Cloudflare dashboard, go to **Workers & Pages → retrac-link → Settings → Variables and Secrets → Add**, choose type **Secret**, name it `DASHBOARD_PASSWORD`, and enter your password. You can also run:

   ```sh
   npx wrangler secret put DASHBOARD_PASSWORD
   ```

   Secrets are kept when you redeploy. Changing the password signs out every dashboard session.

5. Open `https://retrac.link/dashboard` and sign in.

## Local development

```sh
cp .dev.vars.example .dev.vars   # set DASHBOARD_PASSWORD for local use
npm run dev
```

## Notes

- Reserved paths that can't be used as short codes: `dashboard`, `api`, `favicon.ico`, `robots.txt`.
- Short codes and aliases are case-insensitive, so `retrac.link/YT` and `retrac.link/yt` are the same link.
- A short code can't be used as both a link and an alias. If you change a link's short code to one of its own aliases, that alias becomes the main short code.
- Redirects use HTTP 302, so when you change a link's destination, visitors get the new URL right away.
- The dashboard doesn't rate-limit sign-in attempts, so use a long password. You can also add a Cloudflare rate-limiting rule on `POST /dashboard/login`.
