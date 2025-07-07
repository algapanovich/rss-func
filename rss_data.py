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
    {"name": "zdnet-security", "url": "https://www.zdnet.com/topic/security/rss.xml"},
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
    {"name": "nist-upcoming", "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"},
    {"name": "zdi-upcoming", "url": "https://www.zerodayinitiative.com/rss/upcoming/"},
    {"name": "zdi-analyzed", "url": "https://www.zerodayinitiative.com/rss/published/"},
    {"name": "vulners", "url": "https://vulners.com/rss.xml"},
    {"name": "seclists-bugtraq", "url": "https://seclists.org/rss/bugtraq.rss"},
    {"name": "seclists-full", "url": "https://seclists.org/rss/fulldisclosure.rss"},
    {"name": "seclists-oss", "url": "https://seclists.org/rss/oss-sec.rss"},
    {"name": "inthewild", "url": "https://raw.githubusercontent.com/gmatuz/inthewilddb/master/rss.xml"},
    {"name": "center-for-internet-security", "url": "https://www.cisecurity.org/feed/advisories"},
    {"name": "the-hacker-news", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "bleeping-computer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "krebs-on-security", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "schneier-on-security", "url": "https://www.schneier.com/feed/"},
    {"name": "google-security-blog", "url": "http://feeds.feedburner.com/GoogleOnlineSecurityBlog"},
    {"name": "microsoft-security-response-center", "url": "https://msrc.microsoft.com/blog/feed"},
    {"name": "threatpost", "url": "https://threatpost.com/feed/"},
    {"name": "help-net-security", "url": "https://www.helpnetsecurity.com/feed/"},
    {"name": "cvefeed-latest", "url": "https://cvefeed.io/rssfeed/"},
    {"name": "tenable", "url": "https://www.tenable.com/cve/feeds?sort=newest"},
    {"name": "tenable", "url": "https://huntr.com/bounties/hacktivity"},
    {"name": "tenable", "url": "https://cert.europa.eu/publications/security-advisories-rss"},
    {"name": "tenable", "url": "https://www.security-database.com/view-all.php?date=All&sev=All&type=cve"},
    {
        "name": "(Web-)Insecurity Blog",
        "url": "https://security.lauritz-holtmann.de/index.xml"
    },
    {
        "name": "Access Vector - Vulnerability Research & Software Exploitation",
        "url": "https://accessvector.net/rss.xml"
    },
    {
        "name": "Aleph Research - Posts",
        "url": "http://little-canada.org/feeds/output/aleph-posts.rss"
    },
    {
        "name": "Aleph Research - Vulns",
        "url": "http://little-canada.org/feeds/output/aleph-vulns.rss"
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
        "name": "Apple Security Research",
        "url": "https://little-canada.org/feeds/output/applesecurityresearch.rss"
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
        "name": "Blog - Atredis Partners",
        "url": "https://www.atredis.com/blog?format=rss"
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
        "name": "Brendon Tiszka",
        "url": "https://little-canada.org/feeds/output/tiszka.rss"
    },
    {
        "name": "Check Point Research",
        "url": "https://research.checkpoint.com/feed/"
    },
    {
        "name": "Cisco Talos Intelligence Group - Comprehensive Threat Intelligence",
        "url": "http://feeds.feedburner.com/feedburner/Talos"
    },
    {
        "name": "Connor McGarr",
        "url": "https://connormcgarr.github.io/feed.xml"
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
        "name": "Diary of a reverse-engineer",
        "url": "https://doar-e.github.io/feeds/rss.xml?_="
    },
    {
        "name": "Doyensec's Blog",
        "url": "https://blog.doyensec.com/atom.xml"
    },
    {
        "name": "Elttam",
        "url": "https://little-canada.org/feeds/output/elttam.rss"
    },
    {
        "name": "Embrace The Red",
        "url": "https://embracethered.com/blog/index.xml"
    },
    {
        "name": "Exploits.forsale",
        "url": "https://little-canada.org/feeds/output/exploitsforsale.rss"
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
        "name": "Google Security Research Advisories",
        "url": "https://little-canada.org/feeds/output/google-research-advisories.rss"
    },
    {
        "name": "Guido Vranken",
        "url": "https://guidovranken.com/feed/"
    },
    {
        "name": "Hacktus",
        "url": "https://hacktus.tech/rss.xml"
    },
    {
        "name": "Impalabs Blog",
        "url": "https://blog.impalabs.com/feed.xml"
    },
    {
        "name": "Intrigusâ€™ Security Lab",
        "url": "https://intrigus.org/feed.xml"
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
        "name": "Joseph Ravichandran",
        "url": "https://little-canada.org/feeds/output/jprx.rss?_123"
    },
    {
        "name": "Keen Security Lab (Tencent)",
        "url": "https://little-canada.org/feeds/output/tencent-keenlabs.rss"
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
        "name": "Matteo Malvica",
        "url": "https://www.matteomalvica.com/blog/index.xml"
    },
    {
        "name": "Meta - Red Team X - Advisories",
        "url": "https://little-canada.org/feeds/output/meta-redteam-advisories.rss"
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
        "name": "Mozilla Attack & Defense",
        "url": "https://blog.mozilla.org/attack-and-defense/feed/"
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
        "name": "Positive Technologies - learn and secure ",
        "url": "http://feeds.feedburner.com/positiveTechnologiesResearchLab"
    },
    {
        "name": "Posts on Slonser Notes",
        "url": "https://blog.slonser.info/posts/index.xml"
    },
    {
        "name": "Project Zero",
        "url": "http://googleprojectzero.blogspot.com/feeds/posts/default"
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
        "name": "Realmode Labs - Medium",
        "url": "https://medium.com/feed/realmodelabs"
    },
    {
        "name": "Research â€“ Codean Labs",
        "url": "https://codeanlabs.com/blog/category/research/feed/"
    },
    {
        "name": "Rhino Security Labs",
        "url": "https://rhinosecuritylabs.com/feed/"
    },
    {
        "name": "Sam Curry",
        "url": "https://samcurry.net/api/feed.rss"
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
        "name": "Stories by Renwa on Medium",
        "url": "https://medium.com/@renwa/feed"
    },
    {
        "name": "Stratum Security Blog",
        "url": "https://blog.stratumsecurity.com/rss/"
    },
    {
        "name": "Synacktiv | Publications",
        "url": "https://little-canada.org/feeds/output/synacktiv-publications.rss?_=123"
    },
    {
        "name": "Talos - Vulnerability Reports",
        "url": "http://little-canada.org/feeds/output/talos-reports.rss"
    },
    {
        "name": "Taszk.io labs",
        "url": "https://labs.taszk.io/blog/index.xml"
    },
    {
        "name": "Teddy Katzâ€™s Blog",
        "url": "https://blog.teddykatz.com/feed.xml"
    },
    {
        "name": "Trenchant",
        "url": "http://little-canada.org/feeds/output/trenchant.rss"
    },
    {
        "name": "Windows Internals Blog",
        "url": "https://windows-internals.com/feed/"
    },
    {
        "name": "Zero Day Initiative - Blog",
        "url": "https://www.zerodayinitiative.com/blog?format=rss"
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
        "name": "watchTowr Labs - Blog",
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
        "ai",
        "amazon",
        "android",
        "apple",
        "atlassian",
        "aws",
        "breach",
        "ccpa",
        "chatgpt",
        "chrome",
        "confluence",
        "crowdstrike",
        "ddos",
        "docker",
        "docusign",
        "firewall",
        "gcp",
        "gdpr",
        "gemini",
        "github",
        "globalprotect",
        "google cloud",
        "google cloud platform",
        "google workspace",
        "healthcare",
        "hipaa",
        "hitech",
        "hitrust",
        "iam",
        "ids",
        "infoblox",
        "ios",
        "iphone",
        "ips",
        "jamf",
        "jamf pro",
        "jenkins",
        "jira",
        "keeper",
        "kubernetes",
        "log4j",
        "log4shell",
        "lucid",
        "macbook",
        "macos",
        "malware",
        "mfa",
        "microsoft",
        "nist",
        "oauth",
        "okta",
        "openai",
        "openssl",
        "phi",
        "pii",
        "poc",
        "postgresql",
        "powershell",
        "ransomware",
        "saml",
        "scim",
        "siem",
        "slack",
        "soar",
        "social engineering",
        "sso",
        "terraform",
        "threat intelligence",
        "vpn",
        "waf",
        "zoom",
        "cloud armor",
        "hacker one",
        "h1",
        "panorama"
    ]
}
