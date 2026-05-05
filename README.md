# Kalshi X Post Tracker

A single-page tracker for monitoring quote-post performance for X/Twitter posts.

## What it does

- Accepts multiple original X post links.
- Tags each original post by sport: Soccer, NBA, NFL, Baseball, or UFC.
- Stores quote accounts, account IDs, profile photos, views, likes, and RTs.
- Dedupes original posts by post ID and quote posts by quote ID.
- Persists history in browser storage.
- Exports or writes `kalshi-x-history.json` after you choose a history folder.

## How to run locally

1. Create an X Developer app and copy your Bearer Token.
2. Copy `api/.env.example` to `api/.env`.
3. Paste your token into `X_BEARER_TOKEN`.
4. Set `AUTH_DAILY_PASSWORD` and `AUTH_ADMIN_KEY`.
5. Start the protected web app:

```bash
cd api
npm start
```

6. Open `http://localhost:3000`.
7. Enter the daily password.
8. Paste a post link, pick the sport, and load performance.

## Online protection

The Node server now protects the tracker with a daily password, similar to `PlayComp_Distribution`.

- `/` serves the protected tracker.
- `/auth/login` creates a session.
- `/quotes` requires a valid session token.
- `/admin` lets you change the daily password, disable access, and revoke sessions.

Use these environment variables on your host:

```env
X_BEARER_TOKEN=your_x_api_bearer_token
AUTH_APP_ID=kalshi-x-tracker
AUTH_DAILY_PASSWORD=your_daily_password
AUTH_ADMIN_KEY=your_private_admin_key
SESSION_TTL_MS=86400000
```

For Render/Railway/Fly.io, set the start command to:

```bash
npm start
```

and set the root/build directory to:

```text
api
```

## API endpoint

The protected API accepts:

```text
GET /quotes?tweetId=1234567890&maxPages=5
```

It returns:

```json
{
  "tweetId": "1234567890",
  "quotes": []
}
```

Keep `api/.env` private. Do not paste your X token into the HTML before sharing it with friends.
