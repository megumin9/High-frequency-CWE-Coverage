## Mind the Gap: Do SAST Tools Cover High-Frequency CWEs across Programming Languages?

This repository contains the data, evaluation criteria, and experimental results for the research paper: "Mind the Gap: Do SAST Tools Cover High-Frequency CWEs across Programming Languages?". This study presents a large-scale empirical analysis of nine popular Static Application Security Testing (SAST) tools to evaluate their coverage of language-specific high-frequency CWEs across C/C++, Java, and Python.

Project OverviewStatic Application Security Testing (SAST) tools are critical for identifying vulnerabilities early, but existing evaluations often focus on language-agnostic rankings like the MITRE CWE Top 25. This project addresses the mismatch between tool capabilities and developers' actual security needs by:Constructing Language-Specific Datasets: Identifying high-frequency CWEs from 197,016 CVEs reported over the past decade.Evaluating Coverage Gaps: Analyzing 9 popular SAST tools to identify where they fail to detect common vulnerabilities.Assessing Migration Potential: Investigating how multi-language tools can reuse existing checkers to fill coverage gaps.## Repository StructureThe project is organized into the following core components:

CVEData/ Contains the raw and processed vulnerability data used to identify high-frequency CWEs.Primary Source: 197,016 labeled CVE entries from the National Vulnerability Database (NVD) covering 2016 to 2025.Heuristic Labeling: Implementation of the automated labeling process—using file extensions, language names, and 167 manually selected keywords—to map CVEs to specific languages .Accuracy: Manual validation confirms an overall labeling accuracy of 91.5%.

CWEView1000/ Contains the hierarchical data for CWE View 1000 (Research Concepts).Comprehensive Set: Includes 944 CWE types organized by their underlying causes and patterns.Root Categories: Systematic organization of all CWEs into 10 root categories (e.g., CWE-664, CWE-707, CWE-284) to ensure a holistic evaluation.

ToolData/ Technical specifications and checker data for the nine evaluated SAST tools.Analyzed Tools: CodeQL, Semgrep, SonarQube, Cppcheck, Clang Static Analyzer (CSA), Flawfinder, Insider, SpotBugs + FindSecBugs, and Bandit.Tool Metadata: Includes descriptions of analysis paradigms (e.g., Datalog-based semantic engines, symbolic execution, pattern matching) and the specific CWE checkers each tool implements.

RQ Results.xlsx Detailed results for the three core Research Questions (RQs)

## Key Findings 

Language Sensitivity: Vulnerability patterns are highly language-dependent; Jaccard similarity between C/C++ and other languages is only 0.17 to 0.18.C/C++ 

Priority: SAST coverage is lowest for C/C++, highlighting a critical need for tool improvement in this area.

Complementary Strengths: No single tool achieves complete coverage; practitioners should combine tools based on their specific detection goals.

Migration Potential: Leveraging checker migration between languages is a cost-effective way to extend CWE coverage, especially for multi-language tools.