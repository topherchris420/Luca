# Luca

![Architecture](/assets/network-home.png)

### Description

Luca allows you to capture network communications from a smartphone or any device connected to a Wi-Fi access point, then analyze them for suspicious activity using heuristics and Indicators of Compromise (IoCs).

The idea of TinyCheck emerged in a meeting about stalkerware with a [French women's shelter](https://www.centre-hubertine-auclert.fr). During this meeting we talked about how to easily detect [stalkerware](https://stopstalkerware.org/) without installing very technical apps nor doing forensic analysis on the victim's smartphone. The initial concept was to develop a tiny kiosk device based on Raspberry Pi which can be used by non-tech people to test their smartphones against malicious communications issued by stalkerware or any spyware.

Of course, TinyCheck can also be used to spot any malicious communications from cybercrime to state-sponsored implants. It allows the end-user to push their own extended Indicators of Compromise via a backend in order to detect some ghosts over the wire.

<p align="center"><strong>If you need more documentation on how to install it, use it and the internals, don't hesitate to take a look at the <a href="https://github.com/KasperskyLab/TinyCheck/wiki">TinyCheck Wiki</a>.</strong></p>

<p align="center">If you have any question about the project, want to contribute or just send your feedback, <br />don't hesitate to contact us at tinycheck[@]kaspersky[.]com.</p>

### Use cases

TinyCheck can be used in several ways by individuals and entities:

- Over a network - TinyCheck is installed on a network and can be accessed from a workstation via a browser.
- In kiosk mode - TinyCheck can be used as a kiosk to allow visitors to test their own devices.
- Fully standalone - By using a powerbank, two Wi-Fi interfaces or a 4G dongle and a small touch screen [like in this video](https://twitter.com/felixaime/status/1331535790392946689), you can tap any device anywhere.

### Installation

Please check the few steps in the [Wiki's Installation Page](https://github.com/KasperskyLab/TinyCheck/wiki/TinyCheck-installation).

### Meet the frontend

The Luca frontend - available at `http://tinycheck.local` by default - guides users through network capture and reporting. It can connect to an existing Wi-Fi network or create an ephemeral one, capture communications, and present a report in a few simple steps.

![Frontend](/assets/frontend.png)

### Meet the backend

Once installed, you can connect yourself to the TinyCheck backend by browsing the URL `https://tinycheck.local` and accepting the SSL self-signed certificate.

![Backend](/assets/backend.png)

The backend allows you to edit Luca's configuration, add extended IOCs, and manage whitelisted elements to prevent false positives. Several IOCs are included, such as Suricata rules, FreeDNS, name servers, and CIDRs known to host malicious servers.

### Special thanks

**Felix Aime**, for his idea and passion while developing and testing this project. Felix is a main contributor and we really appreciate his work on TinyCheck.

**People who provided some IOCs**
- [Cian Heasley](https://twitter.com/nscrutables) for his android stalkerwares IOC repo, available here: https://github.com/diskurse/android-stalkerware
- [Echap](https://github.com/AssoEchap) for their stalkerwares awesome IOCs repo, available here: https://github.com/AssoEchap/stalkerware-indicators
- [Emilien](https://twitter.com/__Emilien__) for his Stratum rules, available here: https://github.com/kwouffe/cryptonote-hunt
- [Costin Raiu](https://twitter.com/craiu) for his geo-tracker domains, available here: https://github.com/craiu/mobiletrackers/blob/master/list.txt

**Code review**
- Dan Demeter [@_xdanx](https://twitter.com/_xdanx)
- Maxime Granier
- Florian Pires [@Florian_Pires](https://twitter.com/Florian_Pires)
- Ivan Kwiatkowski [@JusticeRage](https://twitter.com/JusticeRage)

**Others**
- GReAT colleagues.
- Tatyana, Kristina, Christina and Arnaud from Kaspersky (Support and IOCs)
- Zeek and Suricata awesome maintainers.
- virtual-keyboard.js.org & loading.io guys.
- Yan Zhu for his awesome Spectre CSS lib (https://picturepan2.github.io/spectre/)
