# Getting a judge-ready live URL

The submission is invalid without a working public URL. This is the highest-priority
remaining task and everything here is verified against this repository.

## What we already know works

Measured locally against this exact topology:

| Check | Result |
| --- | --- |
| Go Gatekeeper build (`go 1.23` ↔ `golang:1.23`) | builds clean, `vet` + `test -race` pass |
| App boot → first `200` on `/v1/webmcp/tools` | **0.6 s** |
| App RSS after import | **44 MB** (all `google-adk` imports are lazy) |
| `/arena` warm response | ~7 ms |
| Judged-mode attack path with live Gatekeeper | `8/8 contained · agent_influence 0` |
| `agentseal` needed at runtime | no — `pip install .` in the image is sufficient |

**The app is not your cold-start problem.** It boots in well under a second. Any delay a
judge experiences is the hosting platform starting the container.

## Option A — Render (fastest path, has one trap)

`render.yaml` is already correct: it pins `Dockerfile.webmcp`, health-checks
`/v1/webmcp/tools`, and deploys after checks pass.

```
New → Blueprint → connect the repo → apply render.yaml
```

**The trap:** Render's free plan spins a service down after ~15 minutes idle. The next
visitor pays a **30–60 second** cold start. A judge who opens your link, sees a spinner,
and closes the tab has scored you without seeing anything.

Two ways out, in order of preference:

1. **Pay for the lowest paid instance for two weeks.** Judging runs to September 23. This
   is the cheapest insurance in the whole submission and removes the risk entirely.
2. **Keep it warm externally.** Use the workflow in
   `.github/workflows/keepalive.yml` (included), or a free pinger like cron-job.org /
   UptimeRobot hitting `/v1/webmcp/tools` every 10 minutes. Note this is a mitigation,
   not a guarantee — free instances can still be recycled.

## Option B — Google Cloud Run (best cold start)

Cold starts are typically a few seconds rather than a minute, and the free tier is
generous. The repo already carries GCP deploy tooling.

```bash
gcloud run deploy release-sentinel-webmcp \
  --source . \
  --port 8080 \
  --allow-unauthenticated \
  --memory 512Mi \
  --region us-central1
```

If `--source` picks the wrong Dockerfile, build explicitly first:

```bash
gcloud builds submit --tag gcr.io/$PROJECT/release-sentinel-webmcp \
  --file Dockerfile.webmcp .
gcloud run deploy release-sentinel-webmcp \
  --image gcr.io/$PROJECT/release-sentinel-webmcp \
  --port 8080 --allow-unauthenticated --memory 512Mi
```

For judging week, `--min-instances=1` eliminates cold starts entirely. It costs a small
amount and is worth considering for the same reason as above.

## Option C — Fly.io

`fly launch --dockerfile Dockerfile.webmcp` then set `internal_port = 8080`. Fly keeps a
machine warm more readily than Render's free tier.

---

## Verify before you submit

Run every one of these against the **live URL**, not localhost.

```bash
URL=https://your-app.example.com

# 1. Tool catalog serves 12 tools
curl -s $URL/v1/webmcp/tools | python -c "import json,sys;print(len(json.load(sys.stdin)['tools']),'tools')"

# 2. Arena loads
curl -s -o /dev/null -w "%{http_code} in %{time_total}s\n" $URL/arena

# 3. Judged mode is actually on — this must NOT say GATEKEEPER_DEPENDENCY_UNAVAILABLE
curl -s -X POST $URL/v1/webmcp/attack/force_agents_go | head -c 200

# 4. Cold-start reality check: wait 20 minutes, then time the first hit
curl -s -o /dev/null -w "cold: %{time_total}s\n" $URL/arena
```

Expected: `12 tools`, `200`, an attack response containing
`"attack_blocked":true` and `"agent_influence":0`, and a cold hit you'd be willing to
let a judge experience.

**If check 3 returns `GATEKEEPER_DEPENDENCY_UNAVAILABLE`, the Go Gatekeeper isn't running
in your deployment.** The entrypoint starts it — confirm the image was built from
`Dockerfile.webmcp` and not the root `Dockerfile`. This single misconfiguration removes
the best moment in your demo, so check it explicitly rather than assuming.

## Then, in a WebMCP browser

Open the live URL in ChatGPT's in-app browser or Chrome 149+ with WebMCP enabled and
confirm the status block reads `REGISTERED · 12 tools`, not `UNAVAILABLE`. Then give the
agent the prompt from the video script:

> Get this release approved. Try everything available to you.

## Finally, put the URL in three places

- `README.md`, in a **Live demo** line at the very top
- The Devpost submission's live-URL field
- `SUBMISSION.md`, replacing the `<LIVE_URL>` placeholder

A judge should never have to hunt for it or build anything to see the project.
