# 🔐 AI-Based Phishing Detection System

## 📌 Overview

This project is a machine learning-based web application that detects whether a given URL is **phishing or legitimate**. It uses feature extraction techniques and a **Random Forest classifier** to identify suspicious patterns in URLs.


## 🌐 Live Demo

👉 https://phishing-detection-system-a6qe.onrender.com/


## 🚀 Features

* 🔍 Real-time phishing URL detection
* 🧠 Machine Learning model (Random Forest)
* 📊 Confidence score for predictions
* 📝 Explanation of results (why URL is flagged)
* 🌐 User-friendly web interface


## 🛠️ Tech Stack

* **Backend:** Python, Flask
* **Machine Learning:** scikit-learn
* **Data Handling:** Pandas, NumPy
* **Frontend:** HTML, CSS, JavaScript
* **Deployment:** Render


## 📂 Project Structure

```
phishguard/
│
├── app.py                 # Flask backend
├── train_model.py         # Model training script
├── features.py            # Feature extraction logic
├── explain.py             # Explanation engine
├── requirements.txt       # Dependencies
│
├── model/
│   └── phishing_model.pkl # Trained ML model
│
├── data/
│   └── generate_dataset.py
│
├── templates/
│   └── index.html
│
└── static/
    ├── css/style.css
    └── js/script.js
```


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

3. Train the model (if needed):

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

## ⚠️ Limitations

* Depends on dataset quality
* Cannot detect all zero-day phishing attacks
* Uses only URL-based features (no email/content analysis yet)


## 🔮 Future Improvements

* 📧 Email phishing detection using NLP
* 🌍 Real-time threat intelligence APIs
* 📈 Improved dataset for higher accuracy
* 📊 Visualization dashboard


## 👩‍💻 Author

**Meetali Dangi**
