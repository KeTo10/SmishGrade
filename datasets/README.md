#SmishGrade Experimental Datasets

This directory contains the specific data snapshots used to evaluate the SmishGrade framework. These files ensure the reproducibility of the results presented in the associated paper.

**Snapshot Date:** November 13, 2025

## File Description

### 1. 'active_phishing_600.txt'
* **Description:** A random sample of 600 active phishing URLs. These links typically represent attacks hosted on a compromised legitimate website.
* **Source:** [phishing-links-ACTIVE.txt](https://github.com/Phishing-Database/Phishing.Database/blob/master/phishing-links-ACTIVE.txt) (Phishing.Database).
* **Use Case:** Evaluating the detection rate against compromised domains

## 2. 'new_domains_300.txt'
*  **Description:** A snapshot of 300 newly registered malicious domains. These represent "zero-day" infrastructure.
*  **Source:** [phishing-domains-NEW-today.txt](https://github.com/Phishing-Database/Phishing.Database/blob/master/phishing-domains-NEW-today.txt) (Phishing.Database).
*  **Use Case:** Evaluating the effectiveness of the "Domain Age" heuristic

## 3. 'tranco_sample_1200.txt'
*  **Description:** The top 1,200 domains from the Tranco list. These represent high-traffic, legitimate websites.
*  **Source:** [Tranco List](https://tranco-list.eu/).
*  **Use Case:** Determining the False Positive Rate and Precision

## Citation and Credit

If you use these specific snapshots, please credit the original data maintainers:

* **Phishing.Database:**
    > Phishing-Database, "Phishing.Database," GitHub repository. [Online]. Available: https://github.com/Phishing-Database/Phishing.Database.

* **Tranco List:**
    > Victor Le Pochat, Tom Van Goethem, Samaneh Tajalizadehkhoob, Maciej Korczyński, and Wouter Joosen. 2019. "Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation," Proceedings of the 26th Annual Network and Distributed System Security Symposium (NDSS 2019). https://doi.org/10.14722/ndss.2019.23386
