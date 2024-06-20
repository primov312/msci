# Vulnerable Versions API

This project provides a REST API service that generates a list of vulnerable versions of a given package from a database of package versions. It uses the `osv.dev` database to check for vulnerabilities and aggregates data from both Debian and Ubuntu ecosystems.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)

## Installation

To set up this project locally, follow these steps:

1. Clone the repository:

   ```sh
   git clone https://github.com/primov312/msci.git
   cd msci
2. install dependencies
   ```sh
    pip install uvicorn httpx fastapi
   ```
##Usage
To run the application, use the following command:

   ```sh
   python run.py
