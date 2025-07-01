### Network Security Project For Phissing Data

**Table of Contents**

- **Introduction**
- **Features**
- **Requirements**
- **Installation**
- **Usage**
- **Configuration**
- **Contributing**

---

## Introduction

Welcome to **NetworkSecurity** – a Python-based project designed to process network phishing data and integrate it with MongoDB. The project reads network data from CSV files (such as phishing data) and converts the data to JSON to store it in a MongoDB database. It incorporates Docker support and a simple HTML template to display data in a tabular format. With a design centered on network security and data processing, the repository lays the groundwork for further extending security checks and analysis on network behavior. 🚀🔒 fileciteturn0file0

---

## Features

- **CSV Data Conversion:** The project includes functionality to convert CSV data (for example, phishing-related information) to JSON so that it can be easily consumed by other components of the system.  
- **MongoDB Integration:** Seamlessly inserts processed data into a MongoDB collection.  
- **Docker Support:** Contains a Dockerfile to build a containerized environment, ensuring consistent deployment across different environments.  
- **HTML Templates:** Provides an HTML template that renders predicted data into a neat, styled table for user-friendly presentation.  
- **Python Packaging:** The project is set up as a Python package with a `setup.py` file, making dependency management and installation straightforward.  
- **Testing Connectivity:** A test script is provided to verify connectivity with MongoDB, ensuring configurations are correct and the connection is secure.

---

## Requirements

To run this project, ensure the following are available on your system:

- **Python 3.10** (or later; the Dockerfile uses python:3.10-slim-buster)  
- **MongoDB:** A running instance of MongoDB (local or a cloud deployment).  
- **Required Python Packages:**  
  - python-dotenv  
  - numpy  
  - pandas  
  - pymongo (including support for SRV connections)  
  - certifi  
  - scikit-learn  
  - dill  
  - pyyaml  
  - mlflow  
  - dagshub  
  - fastapi  
  - uvicorn  
  - tldextract  
  - whois  
  - bs4  
  - beautifulsoup4  
  - streamlit  

All these are specified in the `requirements.txt` file and should be installed automatically when running the setup script or using the Dockerfile fileciteturn0file0, fileciteturn0file1

---

## Installation

Follow these steps to install and set up **NetworkSecurity**:

1. **Clone the Repository:**

   gitshell
   git clone https://github.com/khush-009/networksecurity.git
   cd networksecurity

2. **Install Dependencies:**

   - If you want to install locally:
     
     gitshell
     pip install -r requirements.txt
     
   - Or alternatively, install the package by running:
     
     gitshell
     python setup.py install
     
   The setup script will parse `requirements.txt` and install all dependencies. Ensure that all dependency packages are available and up to date fileciteturn0file1, fileciteturn0file2

3. **Using Docker:**

   The repository includes a Dockerfile that sets up the application environment:

   gitshell
   docker build -t networksecurity .
   docker run -it --rm networksecurity

---

## Usage

Once you have installed the project, here is how you can use it:

- **Data Processing:**

  The main functionality revolves around processing the CSV file (located in `Network_Data/phisingData.csv`) and converting it into JSON records. The script then inserts these records into a MongoDB collection. The main function (typically invoked via `app.py`) will do the following:
  
  - Read the CSV file.
  - Convert the CSV data to JSON format.
  - Insert the JSON records into a specified MongoDB database and collection.
  
  You can test this functionality by running the script:

  gitshell
  python app.py

- **MongoDB Connectivity Test:**

  The `test_mongodb.py` file contains a script to verify connectivity with a MongoDB deployment. This is useful to ensure that your MongoDB URI and network setup are working correctly.

- **Data Presentation:**

  The repository contains an HTML template in the `templates` folder (`table.html`) that renders processed data in a styled table. This can be used as part of a web application or a reporting interface.

---

## Configuration

The project provides several configuration points:

- **CSV File Path:**

  The path to the CSV file is hardcoded in the main script. You may change this path in the script if your CSV files are located elsewhere (e.g., modify the `FILE_PATH` variable in the processing script).

- **MongoDB Connection String:**

  MongoDB connection parameters (URI, database name, and collection name) are set in the scripts. In `test_mongodb.py`, update the URI to include your MongoDB credentials and endpoint. For production or further development, consider using environment variables or a configuration file to avoid hardcoding sensitive information.

- **Docker Configuration:**

  The Dockerfile installs additional dependencies such as the AWS CLI and leverages a slim Python image to keep the container lightweight. Ensure that any environment-specific configurations (like any required environment variables) are correctly set during container runtime.

- **HTML Template:**

  The `templates/table.html` file can be modified to change the data presentation style as per your requirements.

---

## Contributing

Contributions are welcome! If you’d like to enhance the project, please follow these guidelines:

- **Fork the Repository:** Create your own branch to address issues or add new features.
- **Follow the Coding Style:** Ensure that your contributions adhere to the existing Python code style and project structure.
- **Write Tests:** If you add new functionality, please accompany it with test cases. The repository already includes a test for MongoDB connectivity.
- **Submit a Pull Request:** Once your changes are ready, submit a pull request with a clear description of the changes and improvements.

We appreciate clear documentation, thoughtful bug reports, and suggestions that help improve network security for all users! Feel free to open an issue to discuss your ideas.

---

Enjoy using **NetworkSecurity** and happy coding! 🎉🚀
