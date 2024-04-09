# FastAPI Project Setup

## Set Up Python
1. Download and install [Python](https://www.python.org/downloads/) (version 3.7 or above) for your operating system.
2. ADD to PATH 

## Python Virtual Environment
To set up a virtual environment, you will need to have Python installed on your system. Once you have Python installed, you can follow these steps:

1. Open a terminal window.
2. Navigate to the directory where you want to create your virtual environment.
3. Run the following command:

```bash
python -m venv <virtual-environment>
```

Replace <virtual-environment> with name you want for virtual Environment (.venv is most commonly used) 
This will create a new directory <virtual-environment> that contains your virtual environment.

4. To activate your virtual environment, run the following command:
```bash
 <virtual-environment>/bin/activate
```
5. Once your virtual environment is activated, you can install Python packages using the `pip` command from `requirement.txt`.

```bash
 pip install -r requirements.txt
```
6. Open `database.py` and change the database url according to your requirements
7. Open `auth.py` and set your `SECRET_KEY`, `ALGORITHM`,  Email configuration details `ConnectionConfig` and `link_prefix`
8. Use Uvicorn to connect to the database and run your API. 
```bash
 uvicorn main:app --port 8000 --reload
```
You can change port 8000 according to your configuration and --reload is also optional

These are the steps to set up this API

# NOTE:-
    * install Requiremnt specified version Bycrpt module as new version is not supportted by this project 