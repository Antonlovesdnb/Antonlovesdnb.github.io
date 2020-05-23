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

We generate our macro, which outputs an Excel file: 

![](2020-05-23-12-49-17.png)

Now let's take a look at what Sysmon shows us, using the base [Swiftonsecurity Config](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml)

Let's use this basic Splunk Query: 

```sql
index=sysmon EventCode=1 Image=*Excel*
| table Image,ParentImage,CommandLine
```
Which gives us these results: 

![](2020-05-23-12-53-49.png)

Not very interesting, the typical "Excel has Spawned PowerShell or a Command Prompt" detection has failed here, as these macros use techniques which circumvent this particular detection (More details about this are in the Red Canary Blog post linked above) 

If we observe Excel behaviour through something like Procmon, we can see that it loads specific DLLs when a macro is loaded. We can configure Sysmon to look for this type of behaviour.

Let's enhance our Sysmon config a little bit with the following:

```xml
<RuleGroup name="" groupRelation="or">
	<ImageLoad onmatch="include">
		<Rule name="Macro Image Load" groupRelation="or">
			<ImageLoaded condition="end with">VBE7INTL.DLL</ImageLoaded>
			<ImageLoaded condition="end with">VBE7.DLL</ImageLoaded>
			<ImageLoaded condition="end with">VBEUI.DLL</ImageLoaded>
		</Rule>
	</ImageLoad>
</RuleGroup>
```

With this logic, we should see an event when any of the above DLLs are loaded. 

The following Splunk Query: 

```sql
index=sysmon RuleName="Macro Image Load"
| stats values(ImageLoaded) by Image
```

Gives us these results: 

![](2020-05-23-13-01-46.png)

Now we know that a macro was executed by Excel which is a great start. As mentioned earlier, these macro tests break typical process hierarchy detections, so searching for what spawned out of Excel directly is not going to work in this case. 

All we know so far from a detection standpoint is that Excel executed some kind of macro, but we don't know what the macro did or whether it was malicious or not. We can, however, pivot off the data point that we _do_ have and group our events by time to see what was launched around the time that the Excel macro was executed. 

```sql 
index=sysmon 
| bin span=5s _time
| stats values(RuleName),values(Image),values(CommandLine) by _time
```
We group our events into buckets of 5 second time intervals - my thinking here is the malicious processes executed via the macro may not spawn directly from Excel, but they would be grouped together tightly by time. Let's take a look at the results: 

![](2020-05-23-13-31-04.png)

We caught some false positives in our little dragnet, but also found the 'malicious' commands executed by our macro.

Continuing with the Red Canary macro tests, let's look at option 2 in the tests: _Chain Reaction Download and execute with Excel, wmiprvse_

Using the same time bucketing technique, we can see the execution of wmiprvse.exe around the time that an Excel macro was launched: 

![](2020-05-23-13-52-16.png)

Again if we observe Excel behaviour when launching normally versus launching a macro that loads wmiprvse.exe, we can see the wbemdisp.dll being loaded, so let's add that to our Sysmon config as well: 

```xml
<Rule groupRelation="and" name="Office WMI Image Load">
    <Image condition="begin with">C:\Program Files (x86)\Microsoft Office\root\Office16\</Image>
    <ImageLoaded condition="is">C:\Windows\SysWOW64\wbem\wbemdisp.dll</ImageLoaded>
</Rule>
```
This rule will fire when the wbemdisp.dll is loaded by any executable within the Office16 folder, it can be tuned to be more specific as well. 

Here's what the data looks like in Splunk:

![](2020-05-23-14-00-00.png)

Now let's take a look at the Red Canary tests number 4 and 5 - Shell and ShellBrowserWindow. These two methods interact with COM, so we can configure our Sysmon Config as follows: 

```xml
<Rule groupRelation="and" name="Office COM Image Load - Combase">
    <Image condition="begin with">C:\Program Files (x86)\Microsoft Office\root\Office16\</Image>
	<ImageLoaded condition="is">C:\Windows\SysWOW64\combase.dll</ImageLoaded>
</Rule>
<Rule groupRelation="and" name="Office COM Image Load - coml2">
	<Image condition="begin with">C:\Program Files (x86)\Microsoft Office\root\Office16\</Image>
	<ImageLoaded condition="is">C:\Windows\SysWOW64\coml2.dll</ImageLoaded>
</Rule>
<Rule groupRelation="and" name="Office COM Image Load - comsvc">
	<Image condition="begin with">C:\Program Files (x86)\Microsoft Office\root\Office16\</Image>
	<ImageLoaded condition="is">C:\Windows\SysWOW64\comsvcs.dll</ImageLoaded>
</Rule>
```
Firing up our macros again and looking at the following Splunk query: 

```sql
index=sysmon Image=*Excel*
| stats values(ImageLoaded) by Image,RuleName
```
We can see Excel loading the Macro as well as COM DLLs:

![](2020-05-23-14-48-53.png)

Now we know that Excel launched some kind of macro, and used COM, neat!

### Excel 4 Macros

[Outflank](https://www.outflank.nl/) publishes tons of next-level macro techniques regularly, let's take a look at the [following](https://github.com/outflanknl/Scripts/blob/master/ShellcodeToJScript.js) script which is a Proof of Concept which uses Excel 4 Macros to load Shellcode via JScript.

A few things stand out as abnormal using this technique, using the data we have already in our Sysmon config, we can see: 

* Excel Loading a COM DLL
* Excel being launched from a non-standard directory

![](2020-05-23-15-04-43.png)

### RunPE

I used this [Clement Labro's](https://twitter.com/itm4n) implementation of RunPE in my testing, you can grab it [here](https://github.com/itm4n/VBA-RunPE) and read more about it here: 

* https://itm4n.github.io/vba-runpe-part1/
* https://itm4n.github.io/vba-runpe-part2/

Clement describes the technique succinctly:

 >[RunPE] consists in running code inside the memory of a legit process in order to hide its actual activity.

 To my simpleton brain, if I hear "inside the memory of a legit process" I think of injection, so let's configure our Sysmon config to look for this, with the following snippet: 

 ```xml
<RuleGroup name="" groupRelation="or">
    <ProcessAccess onmatch="include">
		<Rule groupRelation="and" name="Office Injection via VBA">
			<SourceImage condition="begin with">C:\Program Files (x86)\Microsoft Office\Root\Office16\</SourceImage>
			<CallTrace condition="contains">\Microsoft Shared\VBA</CallTrace>
	    </Rule>
</ProcessAccess>
 ```

Taking a look at the data this produces, we see Word injecting into Word via VBA: 

![](2020-05-23-15-37-17.png)

