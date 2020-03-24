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

(The resulting files are too large to be hosted on Github, so for now, you can email me if you want them)

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

# Homoglyphs

There already are ressources out there on homoglyphs.

Regarding domain names, the following must be considered:

* IDN display algorithm, depending on browser (such as [2] for Firefox)
* Alphabets and characters authorized for the different TLDs (such as [3] for `.fr`)

Several databases of homoglyphs are available, such as:

* [UriDeep](https://github.com/mindcrypt/uriDeep): "Unicode encoding attacks with machine learning"
* http://homoglyphs.net/
* https://unicode.org/Public/security/latest/confusables.txt

A few tools implements these attacks, along with domain checking:

* https://holdintegrity.com/checker
* [4], already mentionned
* [DnsTwist](https://github.com/elceef/dnstwist), my perosnnal favorite so far
* [HaFinder](https://github.com/loganmeetsworld/homographs-talk.git)

## Homoglyphs in certificate transparency lists

Giving the list obtained through certificate transparency, let's try to find
some homoglyphs domain names.
I try to normalize domain names to an ASCII one, using homoglyphs from [4], with
a few modifications to reduce false positive and includes AFNIC homoglyphs
([3]). Then, the domain is compared to the Alexa top 1M.

The naive implementation (in [homoglyphs.py](homoglyphs.py)) gives back [homoglyphs.txt](homoglyphs.txt). It contains a few false positive but around 2000 homoglyph entries, such as:
```
defense.gouv.fr (defense.göuv.fr - https://defense.xn--guv-sna.fr)
defense.gouv.fr (defense.göüv.fr - https://defense.xn--gv-fkay.fr)
www.com (ԝԝԝ.com - https://xn--07aaa.com)
google.com (ɢᴏᴏɢʟᴇ.com - https://xn--1naa7pn51hcbaa.com)
bitcoin.com (ʙɪᴛᴄᴏɪɴ.com - https://xn--9naa4azkq66k5ba2d.com)
adidas.com (adidȧs.com - https://xn--adids-wcc.com)
aliorbank.pl (aliorbanķ.pl - https://xn--aliorban-kmb.pl)
amazon.com (amɑzon.com - https://xn--amzon-1jc.com)
amazon.com (amäzon.com - https://xn--amzon-hra.com)
amazon.com (amȧzon.com - https://xn--amzon-ucc.com)
amazon.com (amázon.com - https://xn--amzon-yqa.com)
bestchange.com (besțchange.com - https://xn--beschange-smd.com)
bestchange.com (bestchaņge.com - https://xn--bestchage-1vb.com)
bestchange.com (bestchańge.com - https://xn--bestchage-hvb.com)
bestchange.com (bestchaňge.com - https://xn--bestchage-mwb.com)
bestchange.com (bestchanĝe.com - https://xn--bestchane-dkb.com)
bestchange.com (bestchanġe.com - https://xn--bestchane-ilb.com)
bestchange.com (bestchangé.com - https://xn--bestchang-j4a.com)
bestchange.com (bestchangē.com - https://xn--bestchang-jhb.com)
bestchange.com (bestchɑnɡe.com - https://xn--bestchne-0od5n.com)
bestchange.com (bestchánge.com - https://xn--bestchnge-51a.com)
bestchange.com (bestchânge.com - https://xn--bestchnge-g2a.com)
bestchange.com (bestćhange.com - https://xn--besthange-ydb.com)
bestchange.com (beꜱtchange.com - https://xn--betchange-mm26a.com)
bestsecret.com (bestsecɾet.com - https://xn--bestsecet-6fe.com)
facebook.com (facébook.com - https://xn--facbook-dya.com)
facebook.com (facêbook.com - https://xn--facbook-lya.com)
facebook.com (facēbook.com - https://xn--facbook-y7a.com)
facebook.com (facebᴏᴏk.com - https://xn--facebk-m15ba.com)
facebook.com (faceboök.com - https://xn--facebok-f1a.com)
facebook.com (facebôok.com - https://xn--facebok-x0a.com)
facebook.com (faceboȯk.com - https://xn--facebok-y2c.com)
facebook.com (facebooⱪ.com - https://xn--faceboo-2o7e.com)
facebook.com (facebooķ.com - https://xn--faceboo-bhb.com)
facebook.com (faceɓook.com - https://xn--faceook-4bd.com)
facebook.com (faćebook.com - https://xn--faebook-64a.com)
```


# References

* [1] `axeman`: https://github.com/calidog/axeman
* [2] https://wiki.mozilla.org/IDN_Display_Algorithm
* [3] https://www.afnic.fr/medias/documents/Cadre_legal/afnic-charte-de-nommage-2014-12-08.pdf
```
Sont admis au titre de noms de domaine les caractères alphanumériques suivants: a, à, á, â, ã, ä, å, æ, b, c, ç, d, e, è, é, ê, ë, f, g, h, i, ì, í, î, ï, j, k, l, m, n, ñ, o, ò, ó, ô, õ, ö, œ, p, q, r, s, t, u, ù, ú, û, ü,v, w, x, y, ý, ÿ, z, ß, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -(signe moins)
```
* [4] [UriDeep](https://github.com/mindcrypt/uriDeep)
* [5] [DnsTwist](https://github.com/elceef/dnstwist)
* [6] https://holdintegrity.com/checker
* [7] http://homoglyphs.net/
* [8] https://unicode.org/Public/security/latest/confusables.txt
