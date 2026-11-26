# spf-lookup-check

Count the DNS lookups in a domain's SPF record, see which `include:` uses them up, and get a flattened preview. One file, zero dependencies, Node 18+.

SPF allows at most **10 DNS lookups** (RFC 7208, section 4.6.4). Every `include:`, `a`, `mx`, `ptr`, `exists` and `redirect=` counts, including the ones nested inside the providers you include. Go over the limit and receivers return **permerror**: SPF fails, and with DMARC enforcement at Gmail, Yahoo and Microsoft, mail can land in spam or be rejected.

```text
$ node spf-check.mjs github.com
SPF record: v=spf1 ip4:192.30.252.0/22 ip4:172.170.10.240/28 ip4:40.78.162.192/28 ip4:172.170.3.48/28 include:spf.protection.outlook.com include:_netblocks.google.com include:_netblocks2.google.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net include:mktomail.com include:sendgrid.net ip4:62.253.227.114 ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ~all
DNS lookups: 10 / 10

github.com  (10 lookups)
  spf.protection.outlook.com  (0 lookups)
  _netblocks.google.com  (0 lookups)
  _netblocks2.google.com  (0 lookups)
  mail.zendesk.com  (0 lookups)
  _spf.salesforce.com  (1 lookup)
  servers.mcsv.net  (0 lookups)
  mktomail.com  (0 lookups)
  sendgrid.net  (1 lookup)
    ab.sendgrid.net  (0 lookups)

Warnings:
  - _spf.salesforce.com: "exists:%{i}._spf.mta.salesforce.com" uses a macro and can't be flattened
  - _spf.salesforce.com: "exists:%{i}._spf.mta.salesforce.com" can't be flattened; kept as-is
```
(Real output, 26 November 2026. github.com sits exactly at the limit: one more include and its SPF fails.)

## Use

```bash
curl -O https://raw.githubusercontent.com/truone01/spf-lookup-check/main/spf-check.mjs
node spf-check.mjs yourdomain.com             # lookup count + tree + warnings
node spf-check.mjs yourdomain.com --flatten   # plus a flattened preview
node spf-check.mjs yourdomain.com --json      # machine-readable
```

Exit code 1 means permerror (over 10 lookups, more than 2 void lookups, or several SPF records), so you can use it in CI or a cron check.

What it checks:
- total DNS lookups across nested includes and `redirect=`
- void lookups (names that return nothing; more than 2 is a permerror)
- more than one SPF record on a name
- `mx` returning more than 10 hosts
- `ptr` (deprecated), macros and `exists:`, which can't be flattened

## Flattening: fixing it

Ways to get back under 10, best first:
1. **Remove includes you no longer use.** Old newsletter tools and trial CRMs are the usual suspects.
2. **Send from subdomains.** Put marketing mail on `news.example.com` with its own SPF record, so each record stays small.
3. **Flatten.** Replace includes with the IP ranges they resolve to (`--flatten` prints a preview, split into chained records if it's long).

A flattened record is a **snapshot**. When a provider changes its IP ranges, the snapshot goes stale and mail from the new IPs fails SPF. If you flatten, re-check regularly: run this script on a schedule and compare the output.

If you manage **many client domains on Cloudflare**, a hosted version is in development, **SPFTrim**: it keeps each record flattened, re-checks hourly, updates Cloudflare DNS when a provider's IPs change, and keeps a rollback copy. It isn't available yet. Price and waitlist: https://spftrim.2-29-18-178.sslip.io/?ref=github

## Licence

MIT. Issues and pull requests are welcome.
