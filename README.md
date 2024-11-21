Workbook Exporter

Workbook Exporter is a Flask web application that processes CSV files, runs specified exporters on them, and generates output files based on the selected exporters. It also allows users to provide an existing YAML configuration file for processing.
Features

    Upload CSV and optional YAML files
    Select from a list of available exporters
    Process the uploaded files with the chosen exporters
    # Display progress in a live-updating terminal window not working (refresh page to get update on last processed exporters - can process one at a time to choose order in doc)
    Clean up temporary files and download the output

Required Document headers

    Configuration Item Name,Location,Country,Environment,Domain,Hostnames,FQDN,IP Address,Exporter_name_os,OS-Listen-Port,Exporter_name_app,App-Listen-Port,Exporter_name_app_1,App-Listen-Port-1,Exporter_name_app_2,App-Listen-Port-2,Exporter_name_app_3,App-Listen-Port-3,http_2xx,h2xx_url,icmp,ssh-banner,tcp-connect,TCP_Connect_Port,SNMP,Exporter_SSL,

Optional Document headers
    
    comm_string,ssh_username,ssh_password,jmx_ports,snmp_version,snmp_user,snmp_password

Prerequisites

    Python 3.7+
    Flask
    Werkzeug

Installation

    Clone the repository:

    bash

git clone https://github.com/Brownster/workbook_exporter.git

Change to the project directory:

bash

cd workbook_exporter

Install the required packages:

    pip install -r requirements.txt

Usage

    Run the Flask app:

to run gunicorn -w 4 -b 0.0.0.0:8000 workbook_exporter-fe5:app

    arduino

export FLASK_APP=app.py
export FLASK_ENV=development
flask run

On Windows, replace export with set:

arduino

    set FLASK_APP=app.py
    set FLASK_ENV=development
    flask run

    Open your browser and navigate to http://127.0.0.1:5000.

    Upload a CSV file and, optionally, a YAML configuration file.

    Choose the desired exporters from the list.

    Click the "Process" button to run the selected exporters on the uploaded files.

    Monitor the progress in the terminal window.

    Once the processing is complete, click the "Finish and Clean" button to clean up temporary files and return to the initial file upload screen.

Customizing Exporters

You can add or modify exporters in the app.py file. To add a new exporter, define a function for the exporter, then include it in the list of available exporters in the process_file function.
Contributing

If you want to contribute to this project, please submit a pull request with your changes. We welcome any contributions, whether it's fixing bugs, adding new features, or updating documentation.



![image](https://github.com/user-attachments/assets/363a9a3f-c436-42db-8508-e7a7b8322346)




<img width="733" alt="Screenshot 2024-11-21 221744" src="https://github.com/user-attachments/assets/925d1ec2-24a3-4127-94ed-2cf7f4b2ebcd">



