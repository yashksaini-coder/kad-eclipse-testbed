# Repository setup

One-time commands to bring a fresh private repo up to the state
`CONTRIBUTING.md` assumes. Requires `gh` authenticated as the repo owner.

## Create

```sh
gh repo create yashksaini-coder/kad-eclipse-testbed \
  --private \
  --description "Empirical eclipse-attack testbed for rust-libp2p Kademlia" \
  --source . \
  --remote origin \
  --push
```

## Branch protection

Private repos on the free plan cannot use branch protection rules; **rulesets**
do work. If this repo is on a paid plan or is later made public, apply:

```sh
gh api -X PUT repos/yashksaini-coder/kad-eclipse-testbed/branches/main/protection \
  -F required_pull_request_reviews[required_approving_review_count]=0 \
  -F required_pull_request_reviews[dismiss_stale_reviews]=true \
  -F required_status_checks[strict]=true \
  -F 'required_status_checks[contexts][]=fmt' \
  -F 'required_status_checks[contexts][]=clippy' \
  -F 'required_status_checks[contexts][]=test' \
  -F enforce_admins=true \
  -F restrictions=
```

`required_approving_review_count=0` with `enforce_admins=true` is the honest
setting for a solo repo: it cannot manufacture a second reviewer, but it does
force every change through a PR and through green CI, including yours. Raise it
to 1 the moment a second person is involved.

## Settings worth flipping

```sh
gh repo edit yashksaini-coder/kad-eclipse-testbed \
  --enable-squash-merge \
  --enable-merge-commit=false \
  --enable-rebase-merge=false \
  --delete-branch-on-merge \
  --enable-issues \
  --enable-discussions=false
```

## Going public

Before flipping visibility, in order:

1. `git log -p` for anything resembling a credential or a real network target
2. Confirm `SECURITY.md` still describes reality
3. Confirm `docs/results/` contains committed data backing every claim in
   `README.md`
4. Raise required approving reviews to 1 if anyone else has joined
