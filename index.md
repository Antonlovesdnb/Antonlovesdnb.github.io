1. [Hunting Malicious Macros](#first)
---

## Hunting Malicious Macros<a name="first"></a>

Taking a look at the MITRE ATT&CK page for malicious macros, it's clear that this technique is a favourite among APT groups. Microsoft Office is ubiquitous in a corporate office setting and presents defenders with a very large attack surface. 

"Just disable macros" is a great idea, but many critical business processes run on the back of decades-old macros; for better or for worse.

To get a sense of how widely malicious macros are utilized, take a look at the technique via MITRE: [T1566.001](https://attack.mitre.org/beta/techniques/T1566/001/)

In this post I hope to cover detection techniques that provide relatively robust coverage for detecting malicious macros in your own environment. I'll be using Sysmon and a combination of Windows logs in combination with Splunk, although I will provide Sigma rules when possible. I'll also be providing the Sysmon config snippets I used to get the data required. 

Before I dive in, I need to acknowledge that this work **definitely** stands on the shoulders of giants and I'll be referencing their work throughout. 

### Atomic Red Team

Red Canary have done the defensive world a huge solid and have provided a script that generates macros for you so that detections can be tested, so let's start there:

* [Blog Post](https://redcanary.com/blog/testing-initial-access-with-generate-macro-in-atomic-red-team/)

* [Script Used](https://github.com/redcanaryco/atomic-red-team/blob/master/ARTifacts/Initial_Access/generate-macro.ps1)

