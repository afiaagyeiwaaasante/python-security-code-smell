# phase3_rules.py
import os
import csv
from lxml import etree
import re

SAMPLE_XML_DIR = "sample_xml"
REPORT_FILE = "phase3_report.csv"

tainted_variables = set()

# CWE Rules (XPath + metadata)
RULES = [
    #===================================
    # CWE - 798 - Hard-coded Credentials
    #===================================
    {
        # catch string literal assigned to sensitive variable names.
        "cwe": "CWE-798",
        "name": "Hard-coded credentials in assignment",
        "xpath": "//decl/init/value/literal[@type='string']",
        "check": lambda node: any(
            re.search(rf"\b{word}\b", (node.getparent().getparent().findtext("name", "") or '').lower())
                                  for word in ["password", "passwd", "pwd", "secret", "key", "token", "auth"]
        )
    },
    {
        #catch Function arguments where sensitive words appear in parameter names.
        "cwe": "CWE-798",
        "name": "Hardcoded credentials in function call",
        "xpath": "//argument/expr/literal[@type='string']",
        "check": lambda node: any(
            word in (node.getparent().get("argument_name") or "").lower()
            for word in ["password", "passwd", "pwd", "secret", "key", "token", "auth"])
    },
    #========================================
    # CWE - 20 - Improper Input Validation 
    #========================================
    {
        # catch direct calls to input(), eval, exec without validation
        "cwe": "CWE-20",
        "name": "Improper Input Validation Direct use of input(), eval, exec",
        "xpath": "//call/name[text()='input'] | //call/name[text()='eval'] | //call/name[text()='exec']",
        "check": lambda node: any(
            sink in "".join(node.getparent().itertext())
            for sink in ["execute", "os.system", "subprocess", "eval", "exec"]
        )
    },
    {
        # catch direct use of sys.argv
        "cwe": "CWE-20",
        "name": "Improper Input Validation -Direct use of sys.argv",
        "xpath": "//name",
        "check": lambda node: (node.text or "").startswith("sys.argv")
    },
    {
        # catch direct use of os.environ
        "cwe": "CWE-20",
        "name": "Improper Input Validation- Direct use of os.environ",
        "xpath": "//name",
        "check": lambda node: (node.text or "").startswith("os.environ")
    },
    #==========================================================================================
    # CWE - 89 - Improper Neutralization of Special Elements used in SQL Command(SQL Injection)
    #==========================================================================================
    {
        "cwe": "CWE-89",
        "name": "SQL Injection via concatenation",
        "xpath": "//call[name/name='execute']/argument_list/argument/expr[operator='+']",
        "check": lambda node: True
    },
    {
        "cwe": "CWE-89",
        "name": "SQL Injection via f-string",
        "xpath": "//call[name/name='execute']/argument_list/argument/expr/literal[@type='string']",
        "check": lambda node: (node.text or "").startswith("f")
    },
    {
        "cwe": "CWE-89",
        "name": "SQL Injection via str.format()",
        "xpath": "//call[name/name='execute']/argument_list/argument/expr/call[name/name='format']",
        "check": lambda node: True
    },
    {
        "cwe": "CWE-89",
        "name": "SQL Injection via % operator",
        "xpath": "//call[name/name='execute']/argument_list/argument/expr[operator='%']",
        "check": lambda node: True
    },
    {
        "cwe": "CWE-89",
        "name": "SQL Injection via variable argument",
        "xpath": "//call[name/name='execute']/argument_list/argument/expr/name",
        "check": lambda node: not any(
            sibling.tag == "argument" and sibling != node.getparent()
            for sibling in node.getparent().getparent().xpath("./argument")
        )   
    },

    # ==================================================================================================
    # CWE-78: Improper Neutralization  of Special Elements used in an OS Command (OS Command Injection)
    # ==================================================================================================

    {
        "cwe": "CWE-78",
        "name": "Direct command execution (os.system)",
        "xpath": "//call/name[name='os.system']",
        "check": lambda node: True
    },
    {
        "cwe": "CWE-78",
        "name": "Direct command execution (os.popen)",
        "xpath": "//call/name[name='os.popen']",
        "check": lambda node: True
    },
    {
        "cwe": "CWE-78",
        "name": "Direct command execution (subprocess.*)",
        "xpath": "//call/name[name='subprocess.call' or name='subprocess.run' or name='subprocess.Popen']",
        "check": lambda node: True
    },
    {
        "cwe": "CWE-78",
        "name": "subprocess with shell=True",
        "xpath": "//call/argument_list/argument",
        "check": lambda node: (
            "shell=True" in node.getparent().getparent().itertext() or
            any(op in (node.findtext("operator") or "") for op in ["+", "%"]) or
            (node.find("literal") is not None and (node.find("literal").text or "").startswith("f")) or
            any(var in tainted_variables for var in node.itertext())
        )
    },
    {
        "cwe": "CWE-78",
        "name": "Command built via concatenation/formatting",
        "xpath": "//call/argument_list/argument/expr",
        "check": lambda node: any(
            op in (node.find("operator").text if node.find("operator") is not None else "")
            for op in ["+", "%"]
        ) or (
            node.find("call/name/name") is not None
            and node.find("call/name/name").text == "format"
        ) or (
            (node.find("literal") is not None)
            and (node.find("literal").text or "").startswith("f")
        )
    },
    # Track tainted assignments
    {
        "cwe": "CWE-78",
        "name": "Tainted variable assignment (from input/sys.argv/os.environ)",
        "xpath": "//decl_stmt/init/expr",
        "check": lambda node: any(
            source in (node.findtext("call/name") or "") or (node.findtext("name") or "")
            for source in ["input", "sys.argv", "os.environ"]
        )
    },
    #Dangerous sink: os.system with tainted input
    {
        "cwe": "CWE-78",
        "name": "OS Command Injection via os.system",
        "xpath": "//call[name='os.system']/argument_list/argument/expr",
        "check": lambda node: any(
            var in tainted_variables
            for var in (node.itertext())
        )
    },
    # Dangerous sink: subprocess.* with shell=True and tainted input
    {
        "cwe": "CWE-78",
        "name": "OS Command Injection via subprocess.* (shell=True)",
        "xpath": "//call[name[starts-with(.,'subprocess.')]]/argument_list/argument/expr",
        "check": lambda node: (
            any(var in tainted_variables for var in (node.itertext()))
            and "shell" in node.getparent().getparent().itertext().lower()
            and "true" in node.getparent().getparent().itertext().lower()
        )
    },
    # Command built dynamically with tainted data
    {
        "cwe": "CWE-78",
        "name": "Dynamic command concatenation/formatting with tainted input",
        "xpath": "//call/argument_list/argument/expr",
        "check": lambda node: (
            any(var in tainted_variables for var in (node.itertext()))
            and (
                (node.find("operator") is not None and node.find("operator").text in ["+", "%"])
                or (node.find("call/name/name") is not None and node.find("call/name/name").text == "format")
                or ((node.find("literal") is not None) and (node.find("literal").text or "").startswith("f"))
            )
        )
    },

    #========================================================================================================
    # CWE 434 - Unrestricted Upload of File with Dangerous Type
    #========================================================================================================
    {
        "cwe": "CWE-434",
        "name": "Unrestricted upload/download of dangerous file types without integrity check",
        "xpath": (
            "//call[name='urllib.request.urlretrieve' or "
            "name='requests.get' or name='wget.download']"
            "/argument_list//literal"
            "[ends-with(., '.iso') or "
            "ends-with(., '.tar') or "
            "ends-with(., '.tar.gz') or "
            "ends-with(., '.dmg') or "
            "ends-with(., '.deb') or "
            "ends-with(., '.bin') or "
            "ends-with(., '.rpm') or "
            "ends-with(., '.zip')]"
        ),
         "check": lambda node: not any(
        sibling.xpath(".//call/name[contains(., 'hashlib')] | "
                      ".//call/name[contains(., 'gpg')] | "
                      ".//call/name[contains(., 'sha1sum')] | "
                      ".//call/name[contains(., 'sha256sum')]")
        for sibling in node.getparent().itersiblings()
        ),
   },
   #===========================================================================================================
   # CWE 94 - Improper Control of Generation of Code (Code Injection)
   #===========================================================================================================
   {
        "cwe": "CWE-94",
        "name": "Improper control of code generation (Code Injection)",
        "xpath": (
            "//call/name[.='eval' or .='exec' or .='compile' "
            "or .='pickle.loads' or .='yaml.load']"
        ),
        "check": lambda node: not any(
            child.tag == "literal" and child.get("type") == "string"
            for child in node.xpath("./argument_list//literal")
        )
    },
    #=============================================================================================================
    # CWE 269 - Improper Privilege Management
    #=============================================================================================================
    {
        "cwe": "CWE-269",
        "name": "Improper Privilege Management",
        "xpath": (
            "//call/name[.='os.setuid' or .='os.seteuid' or .='os.setgid' or .='os.setegid' or "
            ".='os.system' or .='subprocess.run' or .='subprocess.call' or "
            ".='shutil.chown' or .='os.chown']"
        ),
        "check": lambda node: any(
            "sudo" in "".join(lit.itertext())
            for lit in node.xpath("./argument_list//literal")
        ) or any(
            child.tag == "literal" and child.text == "0"
            for child in node.xpath("./argument_list//literal")
        )
    }, 
    #==============================================================================================================
    # CWE 502 - Deserialization of Untrusted Data
    #==============================================================================================================
    {
        "cwe": "CWE-502",
        "name": "Deserialization of Untrusted Data",
        "xpath": (
            "//call/name[.='pickle.load' or .='pickle.loads' or "
            ".='cPickle.load' or .='cPickle.loads' or "
            ".='yaml.load' or .='marshal.load' or .='marshal.loads']"
        ),
        "check": lambda node: not any(
            "safe_load" in name.text if name is not None else False
            for name in node.xpath(".//name")
        )
    },
    #===============================================================================================================
    # CWE 200 - Exposure of Sensitive Information to an Unauthorized Actor 
    #===============================================================================================================
    {
        "cwe": "CWE-200",
        "name": "Exposure of Sensitive Information",
        "xpath": (
            "//call/name[.='print' or "
            ".='logging.debug' or .='logging.info' or .='logging.warning' or "
            ".='jsonify' or .='Response']"
        ),
        "check": lambda node: (
            # Only flag if variable value itself is printed/logged
            any(keyword in name.text.lower() for name in node.xpath(".//name")
                for keyword in ["password", "secret", "token", "apikey", "key"])
            or
            # Or literal looks like actual data, not just a label
            any("=" in lit.text or len(lit.text) > 12
                for lit in node.xpath(".//literal[@type='string']")
                if any(word in lit.text.lower() for word in ["password", "secret", "token"]))
        )
    },
    #===========================================================================================
    # CWE 732 - Incorrect Permission Assignment for Critical Resource 
    #===========================================================================================
    {
        "cwe": "CWE-732",
        "name": "Incorrect Permission Assignment for Critical Resource",
        "xpath": (
            "//call/name[.='os.chmod' or .='os.mkdir' or .='os.makedirs' "
            "or .='open' or .='tempfile.NamedTemporaryFile']"
        ),
        "check": lambda node: any(
            (lit.text.strip().startswith("0o77") or lit.text.strip().startswith("0o66"))
            and any(kw in node.getparent().itertext().lower()
                    for kw in [".pem", ".key", ".conf", "credential", "secret"])
            for lit in node.xpath("./argument_list//literal")
        )
    },
    #============================================================================================
    # CWE 377 - Insecure Temporary File Creation
    #============================================================================================
    {
        "cwe": "CWE-377",
        "name": "Insecure Temporary File",
        "xpath": (
            "//call/name[.='tempfile.mktemp' or .='open']"
        ),
        "check": lambda node: (
            # Case 1: Direct use of tempfile.mktemp()
            any("mktemp" in name.text for name in node.xpath(".//name")) or
            # Case 2: Manual /tmp/ usage
            any("/tmp/" in "".join(lit.itertext()) for lit in node.xpath(".//literal"))
        )
    },
    #=========================================================================================
    # CWE 703 - Improper Check or Handling of Exceptional Conditions 
    #=========================================================================================
    {
        "cwe": "CWE-703",
        "name": "Improper Check or Handling of Exceptional Conditions",
        "xpath": "//catch",  # catch blocks in srcML representation
        "check": lambda node: (
            # Case 1: Bare except (no type)
            not node.xpath("./type")
            # Broad exception *and* weak handling
            or (
                any(t.text in ["Exception", "BaseException"] for t in node.xpath("./type/name"))
                and not any("raise" in stmt.itertext() for stmt in node.xpath(".//block//expr"))
                and all(stmt.text == "pass" or "print" in stmt.text.lower()
                        for stmt in node.xpath(".//block//expr/name"))
                )
        )
    },
    #==============================================================================================
    # CWE 599 - Missing Validation of Certificate Hostname
    #==============================================================================================
    {
        "cwe": "CWE-599",
        "name": "Missing Validation of Certificate Hostname",
        "xpath": (
            "//call/name[.='ssl.create_default_context' or .='ssl.SSLContext' "
            "or .='ssl._create_unverified_context']"
        ),
        "check": lambda node: (
            # Case 1: Explicit disabling of check_hostname
            any("check_hostname" in name.text and "False" in "".join(lit.itertext())
                for name in node.xpath(".//name")
                for lit in node.xpath(".//literal")) or
            # Case 2: Direct call to ssl._create_unverified_context
            any("ssl._create_unverified_context" in "".join(name.itertext())
                for name in node.xpath(".//name"))
        )
    },
    #======================================================================================
    # CWE 319 - Cleartext Transmission of Sensitive Information
    #=======================================================================================
    {
        "cwe": "CWE-319",
        "name": "Cleartext Transmission of Sensitive Information",
        "xpath": (
            "//call/name[.='requests.get' or .='requests.post' or .='requests.request' or "
            ".='socket.connect' or .='ftplib.FTP' or .='telnetlib.Telnet']"
        ),
        "check": lambda node: (
            # Insecure protocols
            any("http://" in "".join(lit.itertext()) for lit in node.xpath(".//literal")) or
            any("FTP" in "".join(name.itertext()) for name in node.xpath(".//name")) or
            any("Telnet" in "".join(name.itertext()) for name in node.xpath(".//name")) or
            any(lit.text in ["80", "21"] for lit in node.xpath(".//literal")) or
            # Sensitive variable in call
            any(keyword in "".join(node.itertext()).lower()
            for keyword in ["password", "token", "apikey", "auth"])
        )
    }

]

def analyze_file(filepath):
    """Run XPath rules on a single XML file and return findings."""
    findings = []
    try:
        tree = etree.parse(filepath)
        for rule in RULES:
            matches = tree.xpath(rule["xpath"])
            for m in matches:
                if rule["check"](m):
                    findings.append({
                        "file": os.path.basename(filepath),
                        "cwe": rule["cwe"],
                        "name": rule["name"],
                        "snippet": etree.tostring(m.getparent(), encoding="unicode", pretty_print=True).strip()
                    })
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
    return findings

def main():
    all_findings = []
    for fname in os.listdir(SAMPLE_XML_DIR):
        if fname.endswith(".xml"):
            fpath = os.path.join(SAMPLE_XML_DIR, fname)
            findings = analyze_file(fpath)
            all_findings.extend(findings)

    # Save results to CSV
    with open(REPORT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "cwe", "name", "snippet"])
        writer.writeheader()
        writer.writerows(all_findings)

    print(f"Phase 3 report saved to {REPORT_FILE} with {len(all_findings)} findings.")

if __name__ == "__main__":
    main()
