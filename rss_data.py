"""
# Feed data
Includes feed list and keywords list
Keywords contain ignored keywords and static keywords that can be joined with additional lists from other sources
  search_keywords = keywords["static_keywords"]
  search_keywords.extend(additional_keywords)

-> Banned feeds
--> https://securelist.com/feed/ | site throws in random keywords
--> https://feeds.megaphone.fm/darknetdiaries | majorly irrelevant
--> https://www.blackhillsinfosec.com/feed | not relevant most times
--> https://thecyberwire.libsyn.com/rss | spammy
--> https://threatpost.com/ | Defunct No new vulns
Feeds and keywords should be reviewed periodically and updated as needed
"""

rss_feed_list = {
    "news": [
    {"name": "the-hacker-news", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "bleeping-computer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "wired-security", "url": "https://www.wired.com/feed/category/security/latest/rss"},
    {"name": "threatpost", "url": "https://threatpost.com/feed/"},
    {"name": "krebs-on-security", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "schneier-on-security", "url": "https://www.schneier.com/feed/"},
    {"name": "graham-cluley", "url": "https://grahamcluley.com/feed/"},
    {"name": "google-mandiant-blog", "url": "https://www.mandiant.com/resources/blog/rss.xml"},
    {"name": "microsoft-security-response-center", "url": "https://msrc.microsoft.com/blog/feed"},
    {"name": "paloalto-unit42", "url": "https://unit42.paloaltonetworks.com/feed/"},
    {"name": "crowdstrike-blog", "url": "https://www.crowdstrike.com/blog/feed/"},
    {"name": "sophos-naked-security", "url": "https://nakedsecurity.sophos.com/feed/"},
    {"name": "securelist-kaspersky", "url": "https://securelist.com/feed/"},
    {"name": "welivesecurity-eset", "url": "https://www.welivesecurity.com/feed/"},
    {"name": "uk-ncsc", "url": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml"}
    
    ],
    "cve": [
    {
        "name": "(Web-)Insecurity Blog",
        "url": "https://security.lauritz-holtmann.de/index.xml"
    },
    {
        "name": "404 Media",
        "url": "https://www.404media.co/rss/"
    },
    {
        "name": "Access Vector - Vulnerability Research & Software Exploitation",
        "url": "https://accessvector.net/rss.xml"
    },
    {
        "name": "Acronis: Cyber Protection Center",
        "url": "https://www.acronis.com/en-us/tru/feed.xml"
    },
    {
        "name": "Alexander Popov",
        "url": "https://a13xp0p0v.github.io/feed.xml"
    },
    {
        "name": "Android Offensive Security Blog",
        "url": "https://androidoffsec.withgoogle.com/index.xml"
    },
    {
        "name": "Artificial truth",
        "url": "https://dustri.org/b/rss.xml"
    },
    {
        "name": "Assetnote",
        "url": "https://blog.assetnote.io/feed.xml"
    },
    {
        "name": "AttackIQ",
        "url": "https://attackiq.com/blog/feed/"
    },
    {
        "name": "Black Hills Infosec",
        "url": "https://www.blackhillsinfosec.com/feed/"
    },
    {
        "name": "Bleeping Computer",
        "url": "https://www.bleepingcomputer.com/feed/"
    },
    {
        "name": "Blog on STAR Labs",
        "url": "https://starlabs.sg/blog/index.xml"
    },
    {
        "name": "Blog on Shielder",
        "url": "https://www.shielder.it/blog/index.xml"
    },
    {
        "name": "Center for Internet Security",
        "url": "https://www.cisecurity.org/feed/advisories"
    },
    {
        "name": "Check Point Research",
        "url": "https://research.checkpoint.com/feed/"
    },
    {
        "name": "Connor McGarr",
        "url": "https://connormcgarr.github.io/feed.xml"
    },
    {
        "name": "CrowdStrike",
        "url": "https://www.crowdstrike.com/blog/feed/"
    },
    {
        "name": "CVE monitr",
        "url": "https://cvemon.intruder.io/rss/cvetrends/latest"
    },
    {
        "name": "cvefeed-latest",
        "url": "https://cvefeed.io/rssfeed/"
    },
    {
        "name": "Cybersecurity Hub",
        "url": "https://www.cshub.com/rss/articles"
    },
    {
        "name": "DARKNAVY",
        "url": "https://www.darknavy.org/index.xml"
    },
    {
        "name": "DFSEC Research",
        "url": "https://blog.dfsec.com/feed.xml"
    },
    {
        "name": "Darktrace",
        "url": "https://darktrace.com/blog/rss.xml"
    },
    {
        "name": "Decipher",
        "url": "https://decipher.sc/feed/"
    },
    {
        "name": "Diary of a reverse-engineer",
        "url": "https://doar-e.github.io/feeds/rss.xml?_="
    },
    {
        "name": "Doyensec's Blog",
        "url": "https://blog.doyensec.com/atom.xml"
    },
    {
        "name": "Electrospaces.net",
        "url": "http://electrospaces.blogspot.com/feeds/posts/default"
    },
    {
        "name": "Embrace The Red",
        "url": "https://embracethered.com/blog/index.xml"
    },
    {
        "name": "Flashpoint",
        "url": "https://flashpoint.io/feed/"
    },
    {
        "name": "Gamozo Labs Blog",
        "url": "https://gamozolabs.github.io/feed.xml"
    },
    {
        "name": "GitHub Security Lab",
        "url": "https://github.blog/tag/github-security-lab/feed/"
    },
    {
        "name": "Google Security Blog",
        "url": "http://feeds.feedburner.com/GoogleOnlineSecurityBlog"
    },
    {
        "name": "Graham Cluley",
        "url": "https://www.grahamcluley.com/feed/"
    },
    {
        "name": "Guido Vranken",
        "url": "https://guidovranken.com/feed/"
    },
    {
        "name": "Hackread",
        "url": "https://www.hackread.com/feed/"
    },
    {
        "name": "Hacktus",
        "url": "https://hacktus.tech/rss.xml"
    },
    {
        "name": "Have I Been Pwned",
        "url": "https://feeds.feedburner.com/HaveIBeenPwnedLatestBreaches"
    },
    {
        "name": "Heimdal Security",
        "url": "https://heimdalsecurity.com/blog/feed/"
    },
    {
        "name": "Help Net Security",
        "url": "https://www.helpnetsecurity.com/feed/"
    },
    {
        "name": "Huntr Hacktivity",
        "url": "https://huntr.com/bounties/hacktivity"
    },
    {
        "name": "IBM X-Force",
        "url": "https://securityintelligence.com/category/x-force/feed/"
    },
    {
        "name": "Impalabs Blog",
        "url": "https://blog.impalabs.com/feed.xml"
    },
    {
        "name": "Imperva",
        "url": "https://www.imperva.com/blog/feed/"
    },
    {
        "name": "Inthewild DB",
        "url": "https://raw.githubusercontent.com/gmatuz/inthewilddb/master/rss.xml"
    },
    {
        "name": "Intrigus' Security Lab",
        "url": "https://intrigus.org/feed.xml"
    },
    {
        "name": "Intrusion Truth",
        "url": "https://intrusiontruth.wordpress.com/feed/"
    },
    {
        "name": "Isosceles Blog",
        "url": "https://blog.isosceles.com/rss/"
    },
    {
        "name": "Johan Carlsson",
        "url": "https://joaxcar.com/blog/feed/"
    },
    {
        "name": "Kaspersky Labs (Securelist)",
        "url": "https://securelist.com/feed/"
    },
    {
        "name": "Kevin Beaumont (DoublePulsar)",
        "url": "https://doublepulsar.com/feed"
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/"
    },
    {
        "name": "Low-level adventures",
        "url": "https://0x434b.dev/rss/"
    },
    {
        "name": "MDSec",
        "url": "https://www.mdsec.co.uk/feed/"
    },
    {
        "name": "Malwarebytes Labs",
        "url": "https://blog.malwarebytes.com/feed/"
    },
    {
        "name": "Mandiant / Google",
        "url": "https://cloud.google.com/blog/products/identity-security/rss.xml"
    },
    {
        "name": "Matteo Malvica",
        "url": "https://www.matteomalvica.com/blog/index.xml"
    },
    {
        "name": "Meta Red Team X",
        "url": "https://rtx.meta.security/feed.xml"
    },
    {
        "name": "Microsoft Browser Vulnerability Research",
        "url": "https://microsoftedge.github.io/edgevr/feed.xml"
    },
    {
        "name": "Microsoft Security Response Center",
        "url": "https://msrc.microsoft.com/blog/feed"
    },
    {
        "name": "Microsoft Threat Intelligence",
        "url": "https://www.microsoft.com/en-us/security/blog/feed/"
    },
    {
        "name": "Morphisec",
        "url": "https://www.morphisec.com/feed/?post_type=blog"
    },
    {
        "name": "Mozilla Attack & Defense",
        "url": "https://blog.mozilla.org/attack-and-defense/feed/"
    },
    {
        "name": "NCC Group",
        "url": "https://research.nccgroup.com/feed/"
    },
    {
        "name": "Naked Security (by Sophos)",
        "url": "https://nakedsecurity.sophos.com/feed/"
    },
    {
        "name": "NIST Upcoming CVEs",
        "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"
    },
    {
        "name": "ODS Security Research - Nolen Johnson",
        "url": "https://oddsolutions.github.io/feed.xml"
    },
    {
        "name": "Oversecured",
        "url": "https://blog.oversecured.com/feed.xml"
    },
    {
        "name": "PS C:\\Users\\itm4n> _",
        "url": "https://itm4n.github.io/feed.xml"
    },
    {
        "name": "PortSwigger Research",
        "url": "https://portswigger.net/research/rss"
    },
    {
        "name": "Positive Technologies",
        "url": "http://feeds.feedburner.com/positiveTechnologiesResearchLab"
    },
    {
        "name": "Posts on Slonser Notes",
        "url": "https://blog.slonser.info/posts/index.xml"
    },
    {
        "name": "ProofPoint",
        "url": "https://www.proofpoint.com/us/rss.xml"
    },
    {
        "name": "Publications | Hacking Lab",
        "url": "https://kaist-hacking.github.io/publication/index.xml"
    },
    {
        "name": "RET2 Systems Blog",
        "url": "https://blog.ret2.io/feed.xml"
    },
    {
        "name": "Rapid7",
        "url": "https://www.rapid7.com/db/"
    },
    {
        "name": "Realmode Labs - Medium",
        "url": "https://medium.com/feed/realmodelabs"
    },
    {
        "name": "Recorded Future",
        "url": "https://www.recordedfuture.com/feed"
    },
    {
        "name": "Red Canary",
        "url": "https://redcanary.com/feed/"
    },
    {
        "name": "Research - Codean Labs",
        "url": "https://codeanlabs.com/blog/category/research/feed/"
    },
    {
        "name": "Rhino Security Labs",
        "url": "https://rhinosecuritylabs.com/feed/"
    },
    {
        "name": "Risky Business News",
        "url": "https://risky.biz/rss.xml"
    },
    {
        "name": "SANS Internet Storm Center",
        "url": "https://isc.sans.edu/rssfeed.xml"
    },
    {
        "name": "Sam Curry",
        "url": "https://samcurry.net/api/feed.rss"
    },
    {
        "name": "Schneier on Security",
        "url": "https://www.schneier.com/feed/"
    },
    {
        "name": "Sean Heelan's Blog",
        "url": "https://sean.heelan.io/feed/?_"
    },
    {
        "name": "Secfault Security GmbH",
        "url": "https://secfault-security.com/feed.rss"
    },
    {
        "name": "Seclists - Bugtraq",
        "url": "https://seclists.org/rss/bugtraq.rss"
    },
    {
        "name": "Seclists - Full Disclosure",
        "url": "https://seclists.org/rss/fulldisclosure.rss"
    },
    {
        "name": "Seclists - OSS Security",
        "url": "https://seclists.org/rss/oss-sec.rss"
    },
    {
        "name": "Security Latest",
        "url": "https://www.securitylatest.com/feed/"
    },
    {
        "name": "SentinelLabs",
        "url": "https://www.sentinelone.com/labs/feed/"
    },
    {
        "name": "SentinelOne",
        "url": "https://www.sentinelone.com/blog/feed/"
    },
    {
        "name": "Silobreaker",
        "url": "https://www.silobreaker.com/feed/"
    },
    {
        "name": "Sophos: Malware",
        "url": "https://news.sophos.com/en-us/category/malware/feed/"
    },
    {
        "name": "SpiderLabs (Trustwave)",
        "url": "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/?format=feed&type=rss"
    },
    {
        "name": "Stories by Renwa on Medium",
        "url": "https://medium.com/@renwa/feed"
    },
    {
        "name": "Stratum Security Blog",
        "url": "https://blog.stratumsecurity.com/rss/"
    },
    {
        "name": "Talos Intelligence",
        "url": "http://feeds.feedburner.com/talos"
    },
    {
        "name": "Taszk.io labs",
        "url": "https://labs.taszk.io/blog/index.xml"
    },
    {
        "name": "Teddy Katz's Blog",
        "url": "https://blog.teddykatz.com/feed.xml"
    },
    {
        "name": "Tenable CVE Feed",
        "url": "https://www.tenable.com/cve/feeds?sort=newest"
    },
    {
        "name": "The DFIR Report",
        "url": "https://thedfirreport.com/feed/"
    },
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews"
    },
    {
        "name": "The Last Watchdog",
        "url": "https://www.lastwatchdog.com/feed/"
    },
    {
        "name": "Unit 42",
        "url": "https://unit42.paloaltonetworks.com/feed/"
    },
    {
        "name": "Volexity",
        "url": "https://www.volexity.com/blog/feed/"
    },
    {
        "name": "Vulners",
        "url": "https://vulners.com/rss.xml"
    },
    {
        "name": "We Live Security",
        "url": "https://www.welivesecurity.com/feed/"
    },
    {
        "name": "Windows Internals Blog",
        "url": "https://windows-internals.com/feed/"
    },
    {
        "name": "Zero Day Initiative - Upcoming",
        "url": "https://www.zerodayinitiative.com/rss/upcoming/"
    },
    {
        "name": "a place of anatomical precision",
        "url": "https://ysanatomic.github.io/feed.xml"
    },
    {
        "name": "bugs.xdavidhu.me",
        "url": "https://bugs.xdavidhu.me/feed.xml"
    },
    {
        "name": "jub0bs.com",
        "url": "https://jub0bs.com/posts/index.xml"
    },
    {
        "name": "kylebot's Blog",
        "url": "https://blog.kylebot.net/atom.xml"
    },
    {
        "name": "pi3 blog",
        "url": "http://blog.pi3.com.pl/?feed=rss2"
    },
    {
        "name": "secret club",
        "url": "https://secret.club/feed.xml"
    },
    {
        "name": "spaceraccoon.dev",
        "url": "https://spaceraccoon.dev/feed/"
    },
    {
        "name": "watchTowr Labs",
        "url": "https://labs.watchtowr.com/rss/"
    }
    

]
}

keywords = {
    "last_modified": "2025-06-05",
    "ignored": [
        "hiring"
    ],
    "static_keywords": [
        "agi",
        "abnormal",
        "ai",
        "amazon",
        "apple",
        "atlassian",
        "aws",
        "chrome",
        "confluence",
        "crowdstrike",
        "docker",
        "docusign",
        "gcp",
        "gemini",
        "globalprotect",
        "google cloud",
        "google cloud platform",
        "google workspace",
        "healthcare",
        "infoblox",
        "ios",
        "jamf",
        "jamf pro",
        "jenkins",
        "jira",
        "keeper",
        "kubernetes",
        "lucid",
        "macbook",
        "macos",
        "malware",
        "okta",
        "ransomware",
        "slack",
        "zoom",
        "cloud armor",
        "hacker one",
        "h1",
        "panorama",
        "palo alto"
    ]
}
