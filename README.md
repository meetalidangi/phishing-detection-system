# 🔐 AI-Based Phishing Detection System

## 📌 Overview

This project is a machine learning-based web application designed to detect whether a given URL is **phishing or legitimate**.

It analyzes structural and lexical patterns in URLs using feature extraction techniques and applies a **Random Forest classifier** to identify suspicious behavior.

The system not only predicts the result but also provides **clear explanations**, making it more transparent and user-friendly.

---

## 🌐 Live Demo

👉 https://phishing-detection-system-a6qe.onrender.com/

---

## 🚀 Features

* 🔍 Real-time phishing URL detection
* 🧠 Machine Learning model (Random Forest with multiple decision trees)
* 📊 Confidence score for predictions
* 📝 Explanation of results (why a URL is flagged)
* 🌐 Clean and user-friendly web interface

---

## 🛠️ Tech Stack

* **Backend:** Python, Flask
* **Machine Learning:** scikit-learn
* **Data Handling:** Pandas, NumPy
* **Frontend:** HTML, CSS, JavaScript
* **Deployment:** Render

---

## 📂 Project Structure

```
phishguard/
│
├── app.py                 # Flask backend (handles requests & responses)
├── train_model.py         # Model training and evaluation
├── features.py            # URL feature extraction logic
├── explain.py             # Rule-based explanation engine
├── requirements.txt       # Project dependencies
│
├── model/
│   └── phishing_model.pkl # Trained ML model
│
├── data/
│   └── generate_dataset.py
│
├── templates/
│   └── index.html         # Frontend UI
│
└── static/
    ├── css/style.css
    └── js/script.js
```

---

## ▶️ How to Run Locally

1. Clone the repository:

```
git clone https://github.com/meetalidangi/phishing-detection-system.git
cd phishing-detection-system/phishguard
```

2. Install dependencies:

```
pip install -r requirements.txt
```

3. Train the model (if required):

```
python train_model.py
```

4. Run the application:

```
python app.py
```

5. Open in browser:

```
http://localhost:5000
```

---

## 📊 Example

**Input:**

```
http://secure-login-bank.xyz
```

**Output:**

```
Phishing (High Confidence)
```

---

## ⚠️ Limitations & Scope

* The system analyzes URLs **only based on structural and lexical features**
* It does **not verify domain authenticity** against official or trusted sources
* It may classify visually similar domains (e.g., `googel.com`) as legitimate if they do not exhibit strong suspicious patterns
* It does not include email/content-based phishing detection
* Performance depends on dataset quality

👉 This project demonstrates **pattern-based phishing detection**, which is one layer of real-world cybersecurity systems.

---

## 🔮 Future Improvements

* 🔐 Trusted domain verification (banking/e-commerce whitelists)
* 🧠 Domain similarity detection (typosquatting detection like `amazom.com`)
* 🌍 Integration with real-time threat intelligence APIs
* 📧 Email phishing detection using NLP
* 📊 Advanced dashboard and analytics

---

## 👩‍💻 Author

**Meetali Dangi**
