# SmishGrade: Smishing URL Detection Framework

SmishGrade is a heuristics-based framework for smishing detection. SmishGrade analyzes **only the URL string** using a graded heuristic engine.

This project was developed as a **Capstone Project** in Cybersecurity at Fordham University.

## About

SMS phishing (smishing) often utilizes ephemeral infrastructure and "cloaking" techniques to evade detection. SmishGrade addresses this by avoiding webpage content analysis completely. Instead, it assigns a risk score based on observable lexical, host-based, and DNS-based characteristics of the URL.

# Installation

1. **Clone the repository**
    ```bash
    git clone [https://github.com/KeTo10/SmishGrade.git](https://github.com/KeTo10/SmishGrade.git)
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
