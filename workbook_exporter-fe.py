from flask import Flask, render_template, request, send_file
import pandas as pd
import yaml
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/convert', methods=['POST'])
def convert():
    file = request.files['file']
    output_file = 'converted.yaml'

    # Read CSV file into pandas DataFrame
    df = pd.read_csv(file)

    # Filter the data based on the condition
    df_filtered = df[df['Exporter_name_os'] == 'exporter_linux']

    # Create an empty dictionary to hold the final YAML data
    data = {}

    # Loop through the filtered data and add to the dictionary
    for index, row in df_filtered.iterrows():
        data[row['Metric_name']] = {
            'description': row['Description'],
            'labels': row['Label'],
            'type': row['Metric_type']
        }

    # Write dictionary to YAML file
    with open(output_file, 'w') as file:
        yaml.dump(data, file, default_flow_style=False)

    # Send file for download
    return send_file(output_file, as_attachment=True, attachment_filename=output_file)

    # Delete file from server
    os.remove(output_file)

if __name__ == '__main__':
    app.run()
