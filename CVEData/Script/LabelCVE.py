import json
import re
import sys

base_path = "/home/lizhilin/CWEtochecker/nist_CVE/CWEdescriptionresult/"
cve_file = base_path + "CWE_CVE_2016_2025.json"


ccpp_keywords_file = base_path + "CCPPkeyword.json"
java_keywords_file = base_path + "Javakeyword.json"
python_keywords_file = base_path + "Pythonkeyword.json"
other_keywords_file = base_path + "Otherkeyword.json"
nojudge_keywords_file = base_path + "Nojudgekeyword.json"

c_cpp_output = "C_CPP_CVE.json"
java_output = "Java_CVE.json"
python_output = "Python_CVE.json"
other_output = "Other_CVE.json"
conflict_output = "Conflict_CVE.json"
unknown_output = "Unknown_CVE.json"

def load_json_list(filepath):
    try:
        with open(filepath, "r", encoding='utf-8') as f:
            data = json.load(f)
            return [str(kw).lower().strip() for kw in data if str(kw).strip()]
    except Exception as e:
        print(f"error {filepath} - {e}")
        return []

try:
    with open(cve_file, "r", encoding='utf-8') as f:
        cve_list = json.load(f)
except Exception as e:
    print(f"error - {e}")
    sys.exit(1)

ccpp_keywords = load_json_list(ccpp_keywords_file)
java_keywords = load_json_list(java_keywords_file)
python_keywords = load_json_list(python_keywords_file)
other_keywords = load_json_list(other_keywords_file)
nojudge_keywords = load_json_list(nojudge_keywords_file)

def build_strict_pattern(keywords):
    if not keywords: return None
    sorted_kws = sorted(keywords, key=len, reverse=True)
    escaped_kws = [re.escape(kw) for kw in sorted_kws]
    pattern_str = r"\b(?:" + "|".join(escaped_kws) + r")\b"
    return re.compile(pattern_str)


keyword_regexes = {
    "C/C++": build_strict_pattern(ccpp_keywords),
    "Java": build_strict_pattern(java_keywords),
    "Python": build_strict_pattern(python_keywords),
    "Other": build_strict_pattern(other_keywords)
}

nojudge_pattern = build_strict_pattern(nojudge_keywords)

extension_patterns = {
    "C/C++": [r"\.c\b", r"\.cpp\b", r"\.h\b", r"\.hpp\b", r"\.cc\b", r"\.cxx\b"],
    "Java": [r"\.java\b", r"\.jar\b", r"\.class\b", r"\.jsp\b"],
    "Python": [r"\.py\b", r"\.pyc\b", r"\.whl\b"],
    "Other": [
        r"\.cs\b", r"\.js\b", r"\.mjs\b", r"\.sql\b", r"\.go\b", 
        r"\.pas\b", r"\.dpr\b", r"\.vb\b", r"\.vbs\b", r"\.f\b", r"\.f90\b", 
        r"\.sb\b", r"\.rs\b", r"\.php\b", r"\.r\b", r"\.m\b", r"\.asm\b", r"\.s\b", 
        r"\.cbl\b", r"\.cob\b", r"\.rb\b", r"\.pl\b", r"\.swift\b", r"\.ts\b"
    ]
}

name_patterns = {
    "C/C++": [r"\bc\b", r"\bc\+\+\b", r"\bcpp\b"],
    "Java": [r"\bjava\b"],
    "Python": [r"\bpython\b"],
    "Other": [
        r"\bc#\b", r"\bcsharp\b", r"\bjavascript\b", r"\bjs\b", r"\bnode\.js\b",
        r"\bsql\b", r"\bmysql\b", r"\bpostgresql\b", r"\bgo\b", r"\bgolang\b", 
        r"\bdelphi\b", r"\bpascal\b", r"\bvisual basic\b", r"\bvb\b", r"\bvb\.net\b", 
        r"\bfortran\b", r"\bscratch\b", r"\brust\b", r"\bphp\b", r"\br language\b",
        r"\bmatlab\b", r"\bassembly\b", r"\basm\b", r"\bcobol\b", r"\bruby\b", 
        r"\bprolog\b", r"\bswift\b", r"\btypescript\b", r"\bperl\b"
    ]
}

classified = {
    "C/C++": [],
    "Java": [],
    "Python": [],
    "Other": [],
    "Conflict": [],
    "Unknown": []
}

count_nojudge_match = 0 

def detect_categories(desc, pattern_dict, mode='list'):
    detected = set()
    for category, patterns in pattern_dict.items():
        if mode == 'list':
            if any(re.search(p, desc) for p in patterns):
                detected.add(category)
        elif mode == 'regex':
            if patterns and patterns.search(desc):
                detected.add(category)
    return detected

count_processed = 0

for cve in cve_list:
    desc = cve.get("description", "").lower()

    detected_step1 = detect_categories(desc, extension_patterns, mode='list')
    if len(detected_step1) == 1:
        classified[detected_step1.pop()].append(cve)
        count_processed += 1
        continue
    elif len(detected_step1) > 1:
        classified["Conflict"].append(cve)
        count_processed += 1
        continue
    
    detected_step2 = detect_categories(desc, name_patterns, mode='list')
    if len(detected_step2) == 1:
        classified[detected_step2.pop()].append(cve)
        count_processed += 1
        continue
    elif len(detected_step2) > 1:
        classified["Conflict"].append(cve)
        count_processed += 1
        continue

    detected_step3 = detect_categories(desc, keyword_regexes, mode='regex')
    if len(detected_step3) == 1:
        classified[detected_step3.pop()].append(cve)
        count_processed += 1
        continue
    elif len(detected_step3) > 1:
        classified["Conflict"].append(cve)
        count_processed += 1
        continue

    if nojudge_pattern and nojudge_pattern.search(desc):
        classified["Unknown"].append(cve)
        count_nojudge_match += 1 
        count_processed += 1
        continue

    classified["Unknown"].append(cve)
    count_processed += 1
    
    if count_processed % 2000 == 0:
        print(f"num: {count_processed} ...")
'''
# --- 6. 保存结果 ---
def save_json(filename, data):
    with open(filename, "w", encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

save_json(c_cpp_output, classified["C/C++"])
save_json(java_output, classified["Java"])
save_json(python_output, classified["Python"])
save_json(other_output, classified["Other"])
save_json(conflict_output, classified["Conflict"])
save_json(unknown_output, classified["Unknown"])
'''

print("-" * 40)
print(f"处理总量 : {count_processed}")
print(f"C/C++    : {len(classified['C/C++'])}")
print(f"Java     : {len(classified['Java'])}")
print(f"Python   : {len(classified['Python'])}")
print(f"Other    : {len(classified['Other'])}")
print(f"Conflict : {len(classified['Conflict'])}")
print(f"Unknown  : {len(classified['Unknown'])}")
print("-" * 40)