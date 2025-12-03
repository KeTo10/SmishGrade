# SmishGrade: Smishing URL Detection Framework

SmishGrade is a heuristics-based framework for smishing detection. SmishGrade analyzes **only the URL string** using a graded heuristic engine.

This project was developed as a **Capstone Project** in Cybersecurity at Fordham University.

## About

SMS phishing (smishing) often utilizes ephemeral infrastructure and "cloaking" techniques to evade detection. SmishGrade addresses this by avoiding webpage content analysis completely. Instead, it assigns a risk score based on observable lexical, host-based, and DNS-based characteristics of the URL.

# Installation

1. **Clone the repository**
    ```bash
    git clone https://github.com/KeTo10/SmishGrade.git
    cd SmishGrade
    ```
   
2. **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

# Usage
  ```bash
  python smishgrade.py
  ```

## Data Sources

This project relies on external datasets for evaluation. To ensure reproducibility, the specific snapshots used in the experiments are included in the 'datasets/' directory.

* **Benign Dataset:** [Tranco Top Sites](https://tranco-list.eu/)
    > V. Le Pochat, T. Van Goethem, S. Tajalizadehkhoob, M. Korczynski, and W. Joosen, "Tranco: A research-oriented top sites ranking hardened against manipulation," in *Proc. 26th Netw. Distrib. Syst. Secur. Symp. (NDSS)*, 2019.

* **Malicious Dataset:** [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database)
    > Phishing-Database, "Phishing.Database," GitHub repository. [Online]. Available: https://github.com/Phishing-Database/Phishing.Database.

For more details on the specific file snapshots and their use cases, please see the [Datasets README](datasets/README.md).
