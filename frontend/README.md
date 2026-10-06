# Counselor NIDS — dashboard

Next.js frontend for the Django API in `../backend`.

- **Live** (`/`): start/stop a replay, per-detector stats, throughput, how decisions were made
  (unanimous / counselor advice / cross-check / fallback), and the stream of attack alerts —
  pushed over a WebSocket every second.
- **Results** (`/results`): the experiment comparisons and the self-learning curves.

Every chart has a table view. Colours follow the detector, not its position.

```bash
cp .env.example .env.local     # NEXT_PUBLIC_API_URL, default http://localhost:8000
npm install
npm run dev                    # http://localhost:3000
```

`NEXT_PUBLIC_API_URL` is inlined at build time; rebuild after changing it.
