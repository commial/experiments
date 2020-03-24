# Intro

This repository contains various experiments regarding DNS and associated
technologies.

# Certificate transparency

Data comes from the Certificate transparency log list of [Google](https://www.gstatic.com/ct/log_list/log_list.json).

Certificates have been obtained through [1].
Sources collected (ending the 2020/03/22):

* Google 'Argon2020', ~ 10%
* DigiCert Log Server, full
* DigiCert Log Server 2, full
* Cloudflare 'Nimbus2020' Log, full
* Cloudflare 'Nimbus2021' Log, full
* Cloudflare 'Nimbus2022' Log, full
* Cloudflare 'Nimbus2023' Log, full
* Let's Encrypt 'Oak2020' log, full
* Let's Encrypt 'Oak2021' log, full
* Let's Encrypt 'Oak2022' log, full

## Statistics

The extraction of CN and SAN leads to 482 748 070 uniq entries.

The most common sub-domains have been extracted
to [top-1-million-subdomains.txt](top-1-million-subdomains.txt). This list have
been naively made by extracting every parts between dots, excluding the last
two:
```
name,number of occurence

www,102763812
*,72674895
mail,23155980
webmail,18557279
cpanel,17470277
webdisk,17410991
autodiscover,9186418
cpcontacts,5677141
cpcalendars,5674716
vpn,3939493
...
```

These sub-domains can be used for further domain discovery, for instance by
dictionnary-forcing them.

One can notice that some of the entries are quite surprising, such as `kafka,677513`.
The reason is the presence of a lot of cloud instances, potentially ephemerals,
and their multiplicity leads to additionnal weight on cloud sub-domains parts.

This is because this list is only made with the number of uniq entries.

To expose the biggest consumers, [top-1-million-domains.txt](top-1-million-domains.txt) is the inversed list; it contains the top two domain's parts:
```
name,number of occurence

plex.direct,11818030
com.br,9200597
co.uk,9081007
cloudshell.dev,7462615
wd2go.com,6446330
com.au,5654211
azure.com,5064528
co.za,3912553
keenetic.io,2552800
cas.ms,1482468
...
```

Some entries are not surprising, such as `.com.br` or `.co.uk`, giving the construction method.

`plex.direct` is leading the list due to the certificates for each hash-like sub-domains:

```
*.00000050003a4afeafbd308500cd8752.plex.direct
*.00000312dd8f4ac6b881459cbe194f8c.plex.direct
*.0000045648d1432091a654f2fccd5c1d.plex.direct
*.000004a097484bd197bb1bf855477a4d.plex.direct
*.000004b7f307472a9a56d5c685ba424f.plex.direct
*.000008328eb5435eae1e84252b2016e7.plex.direct
*.0000093f8bdd45e1a5c7f9534a2c15ce.plex.direct
*.00000b486c78449f8e411fb181bd3faa.plex.direct
*.00000e8e415d4f59ad8c259a497e31aa.plex.direct
*.000010cbd93947f9a4cbb2801d9c213c.plex.direct
...
```

Want a 0xcafebabe in the URL? Here is one: `*.247cc7f8913e475cafebabe8ebfdc9fc.plex.direct`.

Cloudshell has similar entries, but there are not wildcards:
```
devshell-vm-000000df-28f2-4cc8-bdc9-8417d30f68f2.cloudshell.dev
devshell-vm-00000260-052a-4355-a9ce-d5bfbe4534b4.cloudshell.dev
devshell-vm-000003e7-1c87-417b-bb1d-04eff158e505.cloudshell.dev
devshell-vm-0000078c-f01c-4d7f-a7e2-d5ef7c552fce.cloudshell.dev
devshell-vm-00000c9c-7d13-4cdc-8d12-f22ee035471a.cloudshell.dev
devshell-vm-00000d3d-746d-4f00-8e39-5982e1b15070.cloudshell.dev
devshell-vm-0000119c-69f5-4a52-b4b8-53455f01eafd.cloudshell.dev
devshell-vm-000012f7-f412-43a7-a25e-56f026d132e6.cloudshell.dev
devshell-vm-000015a2-b871-4c62-a22e-b689a38f8695.cloudshell.dev
...
```

## Personnal domains

Several providers or services offer DNS names for their clients, which tends to
be persons rather than entities.

Certificate transparency lists can be a way to list some of them, for instance:

* 289445 entries ending with `synology.me`
* 2722 entries ending with `no-ip.org`
* 71826 entries ending with `ddns.net`
* 11274 entries ending with `hopto.org`

## .onion

A few Tor domains, ending with `.onion`, are also present (listed in [onions.txt](onions.txt)), such as:
```
*.api.dev.nytimes3xbfgragh.onion
*.api.nytimes3xbfgragh.onion
*.api.s5rhoqqosmcispfb.onion
*.api.stg.nytimes3xbfgragh.onion
*.blogs.nytimes3xbfgragh.onion
hzwjmjimhr7bdmfv2doll4upibt5ojjmpo3pbp5ctwcg37n3hyk7qzid.onion
*.stats.qklykfiomrwjhdz4.onion
```

# References

* [1] `axeman`: https://github.com/calidog/axeman

